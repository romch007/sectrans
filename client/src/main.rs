mod nocert;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use clap::{Parser, Subcommand};
use tokio::io::AsyncReadExt;
use tokio_rustls::{
    rustls::{self, pki_types::ServerName},
    TlsConnector,
};

#[derive(Debug, Parser)]
struct Args {
    /// Skip certificate verification (INSECURE!)
    #[arg(short = 'k', long, default_value_t = true)]
    insecure: bool,

    /// Server address
    #[arg(short = 'l', long)]
    address: Option<IpAddr>,

    /// Server port
    #[arg(short, long)]
    port: Option<u16>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// List files present on the server
    List,
    /// Upload a local file
    Upload { filepath: PathBuf },
    /// Download a remote file
    Download { filename: String },
}

#[tokio::main]
async fn main() {
    run().await.unwrap();
}

async fn run() -> anyhow::Result<()> {
    let args = Args::parse();

    let root_cert_store = webpki_roots::TLS_SERVER_ROOTS
        .iter()
        .cloned()
        .collect::<rustls::RootCertStore>();

    let mut config = rustls::ClientConfig::builder()
        .with_root_certificates(root_cert_store)
        .with_no_client_auth();

    if args.insecure {
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(nocert::NoCertificateVerification));
    }

    let connector = TlsConnector::from(Arc::new(config));

    let sockaddr = SocketAddr::new(
        args.address.unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST)),
        args.port.unwrap_or(shared::DEFAULT_PORT),
    );
    let stream = tokio::net::TcpStream::connect(sockaddr).await?;

    let domain = ServerName::try_from("localhost")?.to_owned();

    let stream = connector.connect(domain, stream).await?;
    let (mut reader, mut writer) = tokio::io::split(stream);

    let (packet, file) = match args.command {
        Command::List => (shared::Command::List, None),
        Command::Upload { filepath } => {
            let file = tokio::fs::File::open(&filepath).await?;

            let len = file.metadata().await?.len();
            let filename = filepath
                .file_name()
                .expect("no filename")
                .to_str()
                .unwrap_or_default()
                .to_string();

            (shared::Command::Upload { filename, len }, Some(file))
        }
        Command::Download { filename } => (
            shared::Command::Download {
                filename: filename.clone(),
            },
            None,
        ),
    };

    packet.write(&mut writer).await?;

    if let Some(mut file) = file {
        // Upload file
        tokio::io::copy(&mut file, &mut writer).await?;
    }

    let response = shared::Response::read(&mut reader).await?;

    match response {
        Some(shared::Response::ListResult { files }) => {
            for filename in files {
                println!("{filename}");
            }
        }
        Some(shared::Response::UploadDone) => {
            println!("upload done");
        }
        Some(shared::Response::DownloadStart { filename, len }) => {
            let mut output_file = tokio::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&filename)
                .await?;

            output_file.set_len(len).await?;

            let mut reader = reader.take(len);

            tokio::io::copy(&mut reader, &mut output_file).await?;

            println!("download done");
        }
        Some(shared::Response::Error { message }) => {
            println!("error: {message}");
        }
        None => println!("invalid response"),
    };

    Ok(())
}
