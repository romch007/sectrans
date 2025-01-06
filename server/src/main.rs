use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use anyhow::anyhow;
use clap::Parser;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio_rustls::{
    rustls::{
        self,
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer},
    },
    TlsAcceptor,
};

#[derive(Debug, Parser)]
struct Args {
    /// Listen address
    #[arg(short = 'l', long)]
    pub address: Option<IpAddr>,

    /// Listen port
    #[arg(short, long)]
    pub port: Option<u16>,

    /// Certificate to use
    #[arg(long)]
    pub cert: PathBuf,

    /// Private key to use
    #[arg(long)]
    pub private_key: PathBuf,

    /// Data dir
    #[arg(long)]
    pub dir: PathBuf,
}

#[tokio::main]
async fn main() {
    run().await.unwrap();
}

async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let args = Args::parse();
    check_data_dir(&args.dir).await?;

    tracing::info!("starting server");

    let dir = Arc::new(args.dir);

    let certs = CertificateDer::pem_file_iter(&args.cert)?.collect::<Result<Vec<_>, _>>()?;
    let private_key = PrivateKeyDer::from_pem_file(&args.private_key)?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;
    let acceptor = TlsAcceptor::from(Arc::new(config));

    let sockaddr = SocketAddr::new(
        args.address.unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
        args.port.unwrap_or(shared::DEFAULT_PORT),
    );

    tracing::info!("listening on {sockaddr}");

    let listener = tokio::net::TcpListener::bind(sockaddr).await?;

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        tracing::debug!("peer {peer_addr} connected");

        let acceptor = acceptor.clone();
        let dir = dir.clone();

        tokio::spawn(async move {
            if let Err(e) = handle_connection(acceptor, stream, peer_addr, dir).await {
                tracing::error!("error handling connection: {e}");
            }
        });
    }

    // Ok(())
}

async fn check_data_dir(dir: &Path) -> anyhow::Result<()> {
    let metadata = tokio::fs::metadata(dir).await?;

    if metadata.is_dir() {
        Ok(())
    } else {
        Err(anyhow!("provided data path is not a directory"))
    }
}

async fn handle_connection(
    acceptor: TlsAcceptor,
    stream: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    dir: Arc<PathBuf>,
) -> anyhow::Result<()> {
    let stream = acceptor.accept(stream).await?;

    let (mut reader, mut writer) = tokio::io::split(stream);

    let Some(command) = shared::Command::read(&mut reader).await? else {
        tracing::warn!("invalid packet received from {peer_addr}");
        return Ok(());
    };

    let (response, file) = match command {
        shared::Command::List => (handle_list_files(&dir).await?, None),
        shared::Command::Upload { filename, len } => {
            let path = dir.join(&filename);

            (handle_upload(&path, len, &mut reader).await?, None)
        }
        shared::Command::Download { filename } => {
            let path = dir.join(&filename);

            handle_download(&path).await?
        }
    };

    response.write(&mut writer).await?;

    if let Some(mut file) = file {
        tokio::io::copy(&mut file, &mut writer).await?;
    }

    Ok(())
}

async fn handle_list_files(dir: &Path) -> anyhow::Result<shared::Response> {
    let mut entries = vec![];

    let mut dir = tokio::fs::read_dir(dir).await?;

    while let Some(entry) = dir.next_entry().await? {
        let file_name = entry.file_name().into_string().unwrap_or_default();
        entries.push(file_name);
    }

    Ok(shared::Response::ListResult { files: entries })
}

async fn handle_upload<P, R>(path: P, len: u64, reader: &mut R) -> anyhow::Result<shared::Response>
where
    P: AsRef<Path>,
    R: AsyncRead + Unpin,
{
    let mut file = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)
        .await?;

    file.set_len(len).await?;

    let mut reader = reader.take(len);
    tokio::io::copy(&mut reader, &mut file).await?;

    Ok(shared::Response::UploadDone)
}

async fn handle_download<P>(path: P) -> anyhow::Result<(shared::Response, Option<tokio::fs::File>)>
where
    P: AsRef<Path>,
{
    match tokio::fs::File::open(&path).await {
        Ok(file) => {
            let len = file.metadata().await?.len();
            let filename = path
                .as_ref()
                .file_name()
                .ok_or_else(|| anyhow!("invalid path: file_name() is empty"))?
                .to_str()
                .ok_or_else(|| anyhow!("path is not UTF-8"))?
                .to_string();

            Ok((
                shared::Response::DownloadStart { filename, len },
                Some(file),
            ))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok((
            shared::Response::Error {
                message: "file not found".to_string(),
            },
            None,
        )),
        Err(e) => Err(e)?,
    }
}
