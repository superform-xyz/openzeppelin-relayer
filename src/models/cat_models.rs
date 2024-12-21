use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Cat {
    pub id: u32,
    pub name: String,
    pub age: u8,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct CreateCatRequest {
    pub name: String,
    pub age: u8,
}

impl From<CreateCatRequest> for Cat {
    fn from(req: CreateCatRequest) -> Self {
        Cat {
            id: 0,
            name: req.name,
            age: req.age,
        }
    }
}
