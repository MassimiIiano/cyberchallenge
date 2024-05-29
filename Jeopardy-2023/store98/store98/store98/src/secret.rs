use rocket::request::{FromRequest, Outcome};
use rocket::Request;

use std::convert::Infallible;
use std::env::var;

use diesel::mysql::MysqlConnection;
use diesel::RunQueryDsl;

use crate::models::UserRequest;
use crate::schema::users;

pub struct Flag {
    pub flag: String,
}

impl Flag {
    pub fn new() -> Self {
        let flag = var("FLAG").unwrap_or("CCIT{REDACTED}".to_string());
        Flag { flag: flag }
    }

    pub fn inner(&self) -> String {
        self.flag.clone()
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Flag {
    type Error = Infallible;

    async fn from_request(_request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Flag::new())
    }
}

pub fn init_db(connection: &mut MysqlConnection) {
    let password = var("ADMIN_PASSWORD").unwrap_or("REDACTED".to_string());
    let admin = UserRequest {
        username: "admin".to_string(),
        password: password,
        token: None,
    };
    diesel::insert_or_ignore_into(users::table)
        .values(admin)
        .execute(connection)
        .expect("init_db: Error while insert admin user");
}
