use tokio::fs;
use tokio::fs::OpenOptions;
use tokio::io::AsyncWriteExt;

pub async fn append_to_file(data: &String, name_file: &String) -> Result<(), std::io::Error> {
    if !fs::metadata("Logs").await.is_ok() {
        fs::create_dir_all("Logs").await?;
    }
    let n_file = format!("Logs/{}.txt", name_file);
    let mut file = OpenOptions::new()
        .write(true)
        .append(true)
        .create(true)
        .open(n_file).await?;
    file.write_all(format!("{}\n", data).as_bytes()).await?;
    Ok(())
}