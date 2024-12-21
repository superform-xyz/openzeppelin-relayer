use actix_web::middleware::Logger;
use actix_web::{middleware, App, HttpServer};
use dotenvy::dotenv;
use log::info;
use simple_logger::SimpleLogger;

pub mod config;
pub mod controllers;
pub mod models;
pub mod routes;
pub mod services;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables from .env file
    dotenv().ok();

    let config = config::server_config::ServerConfig::from_env();

    // Initialize logger
    if let Err(e) = SimpleLogger::new().env().init() {
        eprintln!("Failed to initialize logger: {}", e);
    }

    info!("Starting server on {}:{}", config.host, config.port);
    let server = HttpServer::new(|| {
        App::new()
            .wrap(middleware::Compress::default())
            .wrap(middleware::NormalizePath::trim())
            .wrap(middleware::DefaultHeaders::new())
            .wrap(Logger::default())
            .configure(routes::configure_routes)
    })
    .bind((config.host.as_str(), config.port))?
    .shutdown_timeout(5);

    info!("Server running at http://{}:{}", config.host, config.port);

    server.run().await
}
