use std::{error::Error, str::FromStr};

use log4rs::{
    append::{
        console::{ConsoleAppender, Target},
    },
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
};

pub const LOG_DEFAULT_LEVEL: &str = "warning";
const LOG_FORMAT: &str = "{d(%Y-%m-%dT%H:%M:%S%.3f)} {l} {M:<24} - {m}{n}";


fn log_to_stderr(log_verbosity: log::LevelFilter) -> Result<log4rs::Handle, Box<dyn Error>> {
    // Build a stderr logger.
    let stderr = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_FORMAT)))
        .target(Target::Stderr)
        .build();

    let config = Config::builder()
        .appender(Appender::builder().build("stderr", Box::new(stderr)))
        .build(Root::builder().appender("stderr").build(log_verbosity))
        .unwrap();

    let handle = log4rs::init_config(config)?;
    Ok(handle)
}

pub fn configure_logging(log_level: &str) -> Result<log4rs::Handle, Box<dyn Error>> {
    let level = log::LevelFilter::from_str(log_level)?;
    log_to_stderr(level)
}

static INIT: std::sync::Once = std::sync::Once::new();

pub fn test_logger() {
    INIT.call_once(|| {
        stderrlog::new().verbosity(log::Level::Debug).init().unwrap();
    });
}
