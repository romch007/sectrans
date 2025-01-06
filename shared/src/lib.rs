use anyhow::bail;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const DEFAULT_PORT: u16 = 6543;

#[derive(Debug)]
pub enum Command {
    List,
    Upload { filename: String, len: u64 },
    Download { filename: String },
}

impl Command {
    const LIST_ID: u8 = 1;
    const UPLOAD_ID: u8 = 2;
    const DOWNLOAD_ID: u8 = 3;

    pub async fn write<W>(&self, writer: &mut W) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Command::List => {
                writer.write_u8(Self::LIST_ID).await?;
            }
            Command::Upload { filename, len } => {
                writer.write_u8(Self::UPLOAD_ID).await?;
                write_str(writer, filename).await?;
                writer.write_u64(*len).await?;
            }
            Command::Download { filename } => {
                writer.write_u8(Self::DOWNLOAD_ID).await?;
                write_str(writer, filename).await?;
            }
        };

        Ok(())
    }

    pub async fn read<R>(reader: &mut R) -> anyhow::Result<Option<Self>>
    where
        R: AsyncRead + Unpin,
    {
        match reader.read_u8().await? {
            Self::LIST_ID => Ok(Some(Self::List)),
            Self::UPLOAD_ID => {
                let filename = read_str(reader).await?;
                let len = reader.read_u64().await?;

                Ok(Some(Self::Upload { filename, len }))
            }
            Self::DOWNLOAD_ID => {
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
    const LIST_RESULT_ID: u8 = 1;
    const UPLOAD_DONE_ID: u8 = 2;
    const DOWNLOAD_START_ID: u8 = 3;
    const ERROR_ID: u8 = 4;

    pub async fn write<W>(&self, writer: &mut W) -> anyhow::Result<()>
    where
        W: AsyncWrite + Unpin,
    {
        match self {
            Response::ListResult { files } => {
                writer.write_u8(Self::LIST_RESULT_ID).await?;
                writer.write_u64(files.len() as u64).await?;

                for filename in files {
                    write_str(writer, filename).await?;
                }
            }
            Response::UploadDone => {
                writer.write_u8(Self::UPLOAD_DONE_ID).await?;
            }
            Response::DownloadStart { filename, len } => {
                writer.write_u8(Self::DOWNLOAD_START_ID).await?;
                writer.write_u64(*len).await?;
                write_str(writer, filename).await?;
            }
            Response::Error { message } => {
                writer.write_u8(Self::ERROR_ID).await?;
                write_str(writer, message).await?;
            }
        };

        Ok(())
    }

    pub async fn read<R>(reader: &mut R) -> anyhow::Result<Option<Self>>
    where
        R: AsyncRead + Unpin,
    {
        match reader.read_u8().await? {
            Self::LIST_RESULT_ID => {
                let len = reader.read_u64().await? as usize;
                let mut files = Vec::with_capacity(len);

                for _ in 0..len {
                    let filename = read_str(reader).await?;
                    files.push(filename);
                }

                Ok(Some(Self::ListResult { files }))
            }
            Self::UPLOAD_DONE_ID => Ok(Some(Self::UploadDone)),
            Self::DOWNLOAD_START_ID => {
                let len = reader.read_u64().await?;
                let filename = read_str(reader).await?;

                Ok(Some(Self::DownloadStart { filename, len }))
            }
            Self::ERROR_ID => {
                let message = read_str(reader).await?;

                Ok(Some(Self::Error { message }))
            }
            _ => Ok(None),
        }
    }
}

const MAX_STR_LEN: usize = 4096;

async fn write_str<W>(writer: &mut W, input: &str) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if input.len() > MAX_STR_LEN {
        bail!("string is larger than {MAX_STR_LEN}")
    }

    writer.write_u64(input.len() as u64).await?;
    writer.write_all(input.as_bytes()).await?;

    Ok(())
}

async fn read_str<R>(reader: &mut R) -> anyhow::Result<String>
where
    R: AsyncRead + Unpin,
{
    let len = reader.read_u64().await? as usize;
    if len > MAX_STR_LEN {
        bail!("string is larger than {MAX_STR_LEN}")
    }

    let mut buf = vec![0; len];
    reader.read_exact(&mut buf).await?;

    Ok(String::from_utf8(buf).expect("invalid utf8 in str"))
}
