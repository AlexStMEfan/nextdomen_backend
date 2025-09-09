// src/main.rs

use std::sync::Arc;
use clap::Parser;

// Модули
mod raddb;
mod models;
mod directory_service;
mod cli;
mod web;

// Используем cli и web
use cli::Cli;
use web::run_web_server;
use directory_service::DirectoryService;

/// Основная команда
#[derive(clap::Parser)]
#[command(name = "mextdomen")]
#[command(about = "Утилита управления Active Directory", long_about = None)]
struct Args {
    /// Запустить веб-сервер
    #[arg(long, action)]
    web: bool,

    /// Адрес для веб-сервера (например, 127.0.0.1:8080)
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: String,

    /// Путь к данным
    #[arg(short, long, default_value = "data")]
    data_dir: String,

    /// Мастер-ключ (32 байта в hex)
    #[arg(short, long, default_value = "00000000000000000000000000000000")]
    key: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Создаём CLI структуру
    let cli = Cli {
        data_dir: args.data_dir.clone(),
        key: args.key.clone(),
        command: Cli::parse().command, // парсим команду через clap
    };

    // Получаем ключ через parse_key
    let key = Cli::parse_key(&args.key)?;
    let service = Arc::new(DirectoryService::open(&args.data_dir, &key)?);

    if args.web {
        println!("🚀 Запуск веб-API на http://{}", args.addr);
        run_web_server(service, &args.addr).await?;
    } else {
        cli.run().await?;
    }

    Ok(())
}