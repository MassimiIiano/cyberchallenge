use rocket::http::Cookie;
use rocket::http::Status;
use rocket::request::{FromRequest, Outcome};
use rocket::Request;

use std::convert::Infallible;
use std::env::var;

use uuid::Uuid;

use diesel::mysql::MysqlConnection;
use diesel::{self, Connection, QueryDsl, RunQueryDsl, ExpressionMethods};

use rocket::response::{self, Responder, Response};

use crate::models::{CsrfToken, NewCsrfToken};
use crate::schema::csrftokens;

pub struct Database {
    pub connection: MysqlConnection,
}

pub fn establish_connection() -> MysqlConnection {
    let username =
        var("DB_USERNAME").expect("establish_connection: error while retrieving DB username");
    let password =
        var("DB_PASSWORD").expect("establish_connection: error while retrieving DB password");
    let host = var("DB_HOST").expect("establish_connection: error while retrieving DB host");
    let database =
        var("DB_DATABASE").expect("establish_connection: error while retrieving DB database");
    let database_url = &format!("mysql://{}:{}@{}/{}", username, password, host, database);
    let connection = MysqlConnection::establish(database_url)
        .expect(&format!("establish_connection: Error while connecting to {}", host).to_string());

    connection
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Database {
    type Error = Infallible;

    async fn from_request(_request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        Outcome::Success(Database {
            connection: establish_connection(),
        })
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for NewCsrfToken {
    type Error = Infallible;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let token = request
            .cookies()
            .get("csrf-token")
            .and_then(|t| Some(t.value().to_string()))
            .or(Some(String::from("")))
            .expect("Error while obtaining csrf-token cookie");
        let token_decoded = urldecode::decode(token);
        Outcome::Success(NewCsrfToken::new(token_decoded))
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for NewCsrfToken {
    fn respond_to(self, _: &'r Request<'_>) -> response::Result<'o> {
        Response::build()
            .status(Status::Created)
            .header(Cookie::new("csrf-token", self.inner().to_string()))
            .ok()
    }
}

pub fn build_csrf_token(
    connection: &mut MysqlConnection
) -> String {
    let token = Uuid::new_v4().to_string();

    diesel::insert_into(csrftokens::table)
        .values(NewCsrfToken::new(token.clone()))
        .execute(connection)
        .expect(&format!("build_csrf_token: error while inserting token: {}", token.clone()).to_string());

    token
}

pub fn verify_csrf_token(
    provided_csrf_token: String,
    connection: &mut MysqlConnection
) -> Result<CsrfToken, ()> {
    let mut token_list = csrftokens::dsl::csrftokens
        .filter(csrftokens::token.eq(provided_csrf_token))
        .load::<CsrfToken>(connection)
        .map_err(|_| ())?;
    let token = token_list
        .pop()
        .ok_or(())?;
    diesel::delete(csrftokens::dsl::csrftokens.find(token.id))
        .execute(connection)
        .expect(&format!("verify_csrf_token: error while eliminating token: {}", token.token).to_string());
    Ok(token)
}