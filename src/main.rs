mod cache;
mod cidr;
mod config;
mod edns;
mod logger;
mod query;
mod rewrite;
mod security;
mod server;
mod types;
mod utils;
mod version;

use anyhow::Result;
use config::load_config;
use logger::init_logger;
use server::DNSServer;

#[tokio::main]
async fn main() -> Result<()> {
    let mut config_file = None;
    let mut generate_config = false;
    let mut show_version = false;

    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "-config" => {
                if i + 1 < args.len() {
                    config_file = Some(args[i + 1].clone());
                    i += 1;
                }
            }
            "-generate-config" => generate_config = true,
            "-version" => show_version = true,
            _ => {}
        }
        i += 1;
    }

    if show_version {
        println!("ZJDNS Server");
        println!("Version: {}", version::VERSION);
        return Ok(());
    }

    if generate_config {
        let example = config::generate_example_config()?;
        println!("{}", example);
        return Ok(());
    }

    init_logger("info");

    let config = load_config(config_file.as_deref()).await?;
    init_logger(&config.server.log_level);

    let server = DNSServer::new(config).await?;
    server.start().await?;
    Ok(())
}
