// src/main.rs

use clap::Parser;
use std::sync::Arc;

mod cli;
mod web;
mod directory_service;
mod models;
mod raddb;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct CliArgs {
    #[command(subcommand)]
    command: AppCommand,
}

#[derive(clap::Subcommand)]
enum AppCommand {
    /// Запустить REST API сервер
    Web {
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        addr: String,
    },
    /// Запустить CLI режим
    Cli,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = CliArgs::parse();
    let config = load_config()?;
    let key = decode_key(&config.master_key_hex)?;

    // Открываем сервис
    let service = Arc::new(directory_service::DirectoryService::open(&config.db_path, &key)?);

    match args.command {
        AppCommand::Web { addr } => {
            println!("🌐 Запуск REST API на http://{}", addr);
            web::run_web_server(service, &addr).await?;
        }
        AppCommand::Cli => {
            println!("💻 Запуск CLI режима");
            cli::run_cli().await?;
        }
    }

    Ok(())
}

/// Конфигурация из `config.yaml`
#[derive(serde::Deserialize)]
struct Config {
    db_path: String,
    master_key_hex: String,
}

fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    let file = std::fs::File::open("config.yaml")?;
    let config: Config = serde_yaml::from_reader(file)?;
    Ok(config)
}

fn decode_key(hex: &str) -> Result<[u8; 32], hex::FromHexError> {
    let mut key = [0u8; 32];
    hex::decode_to_slice(hex, &mut key)?;
    Ok(key)
}