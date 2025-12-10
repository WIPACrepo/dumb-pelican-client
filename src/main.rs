mod credentials;
mod error;
mod logging;
mod pelican;
mod transfer;

use std::backtrace::Backtrace;
use std::error::Error;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Cli {
    #[arg(short, long)]
    log_level: Option<String>,

    #[arg(short, long, default_value_t = 1)]
    retries: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Object(ObjectCommands),
}

#[derive(Parser, Debug)]
struct ObjectCommands {
    #[command(subcommand)]
    command: ObjectSubcommands,
}

#[derive(Subcommand, Debug)]
enum ObjectSubcommands {
    Get { url: String, filename: String },
    Put { filename: String, url: String },
}

fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    // set up logging
    let log_level = match cli.log_level {
        None => logging::LOG_DEFAULT_LEVEL.to_string(),
        Some(level) => level,
    };
    let _log_handle = logging::configure_logging(log_level.as_str());

    // get credentials
    let creds = credentials::Credentials::from_condor()?;

    // get transfer info
    let transfer = match &cli.command {
        Commands::Object(sub) => match &sub.command {
            ObjectSubcommands::Get { url, filename } => {
                transfer::Transfer::new(url.clone(), filename.clone(), transfer::Verb::Get)
            }
            ObjectSubcommands::Put { filename, url } => {
                transfer::Transfer::new(url.clone(), filename.clone(), transfer::Verb::Put)
            }
        },
    };

    // get Pelican info
    let origin = pelican::PelicanInfo::from_url(transfer.url.as_str())?;

    // do transfer
    transfer.execute(&creds, &origin)?;

    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(_) => ExitCode::SUCCESS,
        Err(e) => {
            log::info!("Backtrace: {}", Backtrace::force_capture());
            log::error!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}
