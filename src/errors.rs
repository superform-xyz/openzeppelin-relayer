use actix_web::{HttpResponse, ResponseError};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum RelayerError {
    #[error("Internal Server Error")]
    InternalError,

    #[error("Not Found: {0}")]
    NotFound(String),

    #[error("Bad Request: {0}")]
    BadRequest(String),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

impl ResponseError for RelayerError {
    fn error_response(&self) -> HttpResponse {
        match self {
            RelayerError::InternalError => {
                HttpResponse::InternalServerError().json(self.to_string())
            }
            RelayerError::NotFound(msg) => HttpResponse::NotFound().json(msg),
            RelayerError::BadRequest(msg) => HttpResponse::BadRequest().json(msg),
            RelayerError::Unauthorized(msg) => HttpResponse::Unauthorized().json(msg),
        }
    }
}
