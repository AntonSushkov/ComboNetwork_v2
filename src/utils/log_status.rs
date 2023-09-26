use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::path::Path;
use csv::{ReaderBuilder, WriterBuilder};
use lazy_static::lazy_static;
use tokio::sync::Mutex;
use std::io::Error as IoError;

lazy_static! {
    static ref CSV_MUTEX: Mutex<()> = Mutex::new(());
}

struct Loggers {
    index: String,
    address: String,
    tasks: HashMap<String, String>,
}

pub async fn log_status(index: usize, address: &str, task: &str, status: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _guard = CSV_MUTEX.lock().await;

    let path = Path::new("Logs/result.csv");
    if !path.exists() {
        let mut file = File::create(&path)?;
        let mut wtr = WriterBuilder::new().from_writer(file);
        wtr.write_record(&["index", "address"])?; // Writing default headers
        wtr.flush()?; // Explicitly flushing and closing the writer
    }

    let mut rdr = ReaderBuilder::new().from_path(&path)?;
    let mut records: HashMap<String, Loggers> = HashMap::new();
    let mut all_tasks: HashSet<String> = HashSet::new();
    let headers: Vec<String> = rdr.headers()?.iter().map(|h| h.to_string()).collect();

    for result in rdr.records() {
        let record = result?;
        let index = record[0].to_string();
        let address = record[1].to_string();
        let mut tasks: HashMap<String, String> = HashMap::new();

        for (i, field) in headers.iter().enumerate().skip(2) {
            tasks.insert(field.to_string(), record[i].to_string());
            all_tasks.insert(field.to_string());
        }

        records.insert(index.clone(), Loggers {
            index,
            address,
            tasks,
        });
    }

    let record = records.entry(index.to_string()).or_insert_with(|| Loggers {
        index: index.to_string(),
        address: address.to_string(),
        tasks: HashMap::new(),
    });

    record.address = address.to_string();
    record.tasks.insert(task.to_string(), status.to_string());
    all_tasks.insert(task.to_string());

    let file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&path)?;

    let mut wtr = WriterBuilder::new().from_writer(file);

    let mut headers = vec!["index".to_string(), "address".to_string()];
    headers.extend(all_tasks.iter().cloned());
    wtr.write_record(&headers)?;

    for (_, record) in records {
        let mut row = vec![record.index.clone(), record.address.clone()];
        for task in &all_tasks {
            row.push(record.tasks.get(task).cloned().unwrap_or_default());
        }
        wtr.write_record(&row)?;
    }

    wtr.flush()?; // Explicitly flushing the writer
    Ok(())
}
