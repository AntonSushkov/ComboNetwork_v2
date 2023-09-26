extern crate humantime;
use std::time::{SystemTime};
use std::fs;

pub fn setup_logger() -> Result<(), fern::InitError> {
    if !fs::metadata("Logs").is_ok() {
        fs::create_dir_all("Logs")?;
    }

    fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "[{} {} {}] {}",
                humantime::format_rfc3339_seconds(SystemTime::now()),
                record.level(),
                record.target(),
                message
            ))
        })
        // Set a global filter to `Info` level.
        // This will allow through `Info`, `Warn`, `Error`, and higher levels.
        .level(log::LevelFilter::Info)
        .chain(fern::log_file("Logs/logs.log")?)
        // Set up a custom filter for `stdout` to allow only `Info` and `Error` levels.
        .chain(fern::Dispatch::new()
            .filter(|record| matches!(record.level(), log::Level::Info | log::Level::Error))
            .chain(std::io::stdout())
        )
        .apply()?;
    Ok(())
}
