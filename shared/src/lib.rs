use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DEFAULT_PORT: u16 = 6543;

#[derive(Debug)]
pub enum Command {
    List,
    Upload { filename: String, len: u64 },
    Download { filename: String },
}

impl Command {
    pub async fn write<W>(&self, writer: &mut W) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Command::List => {
                writer.write_u8(1).await?;
            }
            Command::Upload { filename, len } => {
                writer.write_u8(2).await?;
                write_str(writer, filename).await?;
                writer.write_u64(*len).await?;
            }
            Command::Download { filename } => {
                writer.write_u8(3).await?;
                write_str(writer, filename).await?;
            }
        };

        Ok(())
    }

    pub async fn read<R>(reader: &mut R) -> std::io::Result<Option<Self>>
    where
        R: AsyncRead + Unpin,
    {
        match reader.read_u8().await? {
            1 => Ok(Some(Self::List)),
            2 => {
                let filename = read_str(reader).await?;
                let len = reader.read_u64().await?;

                Ok(Some(Self::Upload { filename, len }))
            }
            3 => {
                let filename = read_str(reader).await?;

                Ok(Some(Self::Download { filename }))
            }
            _ => Ok(None),
        }
    }
}

#[derive(Debug)]
pub enum Response {
    ListResult { files: Vec<String> },
    UploadDone,
    DownloadStart { filename: String, len: u64 },
    Error { message: String },
}

impl Response {
    pub async fn write<W>(&self, writer: &mut W) -> std::io::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Response::ListResult { files } => {
                writer.write_u8(1).await?;
                writer.write_u64(files.len() as u64).await?;

                for filename in files {
                    write_str(writer, filename).await?;
                }
            }
            Response::UploadDone => {
                writer.write_u8(2).await?;
            }
            Response::DownloadStart { filename, len } => {
                writer.write_u8(3).await?;
                writer.write_u64(*len).await?;
                write_str(writer, filename).await?;
            }
            Response::Error { message } => {
                writer.write_u8(4).await?;
                write_str(writer, message).await?;
            }
        };

        Ok(())
    }

    pub async fn read<R>(reader: &mut R) -> std::io::Result<Option<Self>>
    where
        R: AsyncRead + Unpin,
    {
        match reader.read_u8().await? {
            1 => {
                let len = reader.read_u64().await? as usize;
                let mut files = Vec::with_capacity(len);

                for _ in 0..len {
                    let filename = read_str(reader).await?;
                    files.push(filename);
                }

                Ok(Some(Self::ListResult { files }))
            }
            2 => Ok(Some(Self::UploadDone)),
            3 => {
                let len = reader.read_u64().await?;
                let filename = read_str(reader).await?;

                Ok(Some(Self::DownloadStart { filename, len }))
            }
            4 => {
                let message = read_str(reader).await?;

                Ok(Some(Self::Error { message }))
            }
            _ => Ok(None),
        }
    }
}

async fn write_str<W>(writer: &mut W, input: &str) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_u64(input.len() as u64).await?;
    writer.write_all(input.as_bytes()).await?;

    Ok(())
}

async fn read_str<R>(reader: &mut R) -> std::io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u64().await? as usize;

    let mut buf = vec![0; len];
    reader.read_exact(&mut buf).await?;

    Ok(String::from_utf8(buf).expect("invalid utf8 in str"))
}
