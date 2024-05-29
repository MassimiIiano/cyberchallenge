#[macro_use]
extern crate rocket;
extern crate data_encoding;
extern crate rand;

use rocket::fs::FileServer;
use rocket::response::status::{Conflict, Created, Unauthorized};
use rocket::serde::json::Json;

use std::collections::HashMap;

use diesel::ExpressionMethods;
use diesel::{self, sql_query, BoolExpressionMethods, QueryDsl, RunQueryDsl, SaveChangesDsl};

use diesel_migrations::{embed_migrations, EmbeddedMigrations, MigrationHarness};
use simplelog::{ColorChoice, CombinedLogger, LevelFilter, TermLogger, TerminalMode};
use uuid;

mod models;
mod schema;
mod secret;
mod utils;
use crate::models::{Product, User, UserRequest, Uuid, NewCsrfToken};
use crate::schema::users;
use crate::secret::{init_db, Flag};
use crate::utils::{
    build_csrf_token, establish_connection, verify_csrf_token, Database,
};

pub const MIGRATIONS: EmbeddedMigrations = embed_migrations!("migrations/");

// Catchers

#[catch(404)]
fn not_found_catcher(_req: &rocket::Request) -> &'static str {
    ""
}

#[catch(401)]
fn unauthorized_catcher(_req: &rocket::Request) -> &'static str {
    ""
}

#[catch(400)]
fn bad_request_catcher(_req: &rocket::Request) -> &'static str {
    ""
}

#[catch(422)]
fn unprocessable_entity_catcher(_req: &rocket::Request) -> &'static str {
    ""
}

#[catch(500)]
fn internal_server_error_catcher(_req: &rocket::Request) -> &'static str {
    ""
}

// Routes

#[get("/csrf")]
async fn csrf_token(
    database: Database
) -> NewCsrfToken {
    let mut connection = database.connection;
    NewCsrfToken::new(build_csrf_token(&mut connection))
}

#[get("/search?<name>")]
async fn search_products(
    name: Option<String>,
    database: Database,
    csrf_token: NewCsrfToken,
) -> Result<Json<Vec<Product>>, Conflict<Json<HashMap<String, String>>>> {
    let mut connection = database.connection;

    if let Err(_) = verify_csrf_token(csrf_token.inner().to_string(), &mut connection) {
        let mut hm: HashMap<String, String> = HashMap::new();
        hm.insert(
            "error".to_string(),
            format!("invalid csrf_token").to_string(),
        );
        return Err(Conflict(Some(Json(hm))));
    };

    // so smart, so brilliant, so secure, so lovely, so perfect sanitization
    let secure_name = name
        .clone()
        .or(Some("?".to_string()))
        .ok_or_else(|| {
            let mut hm: HashMap<String, String> = HashMap::new();
            hm.insert(
                "error".to_string(),
                format!("Failure while sanitizing {:?}", name).to_string(),
            );
            Conflict(Some(Json(hm)))
        })?
        .replace("'", "\\'");
    let query = format!("SELECT * FROM products WHERE name LIKE '%{}%'", secure_name);
    info!("Executing query: {}", query);

    let products = sql_query(query.clone())
        .load::<Product>(&mut connection)
        .map_err(|_| {
            let mut hm: HashMap<String, String> = HashMap::new();
            hm.insert(
                "error".to_string(),
                format!("Failure while executing the following query: {}", query).to_string(),
            );
            Conflict(Some(Json(hm)))
        })?;

    Ok(Json(products))
}

#[post("/session", data = "<login_data>")]
async fn create_session(
    login_data: Json<UserRequest>,
    database: Database,
    flag: Flag,
) -> Result<Json<HashMap<String, Option<String>>>, Unauthorized<()>> {
    let mut connection = database.connection;

    let users_list = users::dsl::users
        .filter(
            users::username
                .eq(login_data.username.clone())
                .and(users::password.eq(login_data.password.clone())),
        )
        .load::<User>(&mut connection)
        .expect("create_session: Error while loading users");
    let user_ref = users_list.first().ok_or(Unauthorized(None))?;
    let mut user = (*user_ref).clone();
    let user_id = Uuid::new(uuid::Uuid::new_v4());
    user.token = Some(user_id);
    user.save_changes::<User>(&mut connection)
        .expect("create_session: Error while saving user token");

    let mut result: HashMap<String, Option<String>> = HashMap::new();
    let flag = if let "admin" = &user.username[..] {
        Some(flag.inner())
    } else {
        None
    };

    result.insert("token".to_string(), Some(user_id.inner().to_string()));
    result.insert("flag".to_string(), flag);
    Ok(Json(result))
}

#[post("/users", data = "<user>")]
async fn create_user(
    user: Json<UserRequest>,
    database: Database,
) -> Result<Created<()>, Conflict<()>> {
    let mut connection = database.connection;

    diesel::insert_into(users::table)
        .values(&*user)
        .execute(&mut connection)
        .map_err(|_| Conflict(None))?;

    Ok(Created::new("/"))
}

#[launch]
async fn rocket() -> _ {
    #[cfg(debug_assertions)]
    let max_log_level = LevelFilter::Debug;
    #[cfg(not(debug_assertions))]
    let max_log_level = LevelFilter::Info;

    let stdout_logger_config = simplelog::ConfigBuilder::new()
        .set_time_level(LevelFilter::Off)
        .set_thread_level(LevelFilter::Off)
        .set_target_level(LevelFilter::Off)
        .build();

    CombinedLogger::init(vec![TermLogger::new(
        max_log_level,
        stdout_logger_config,
        TerminalMode::Stderr,
        ColorChoice::Auto,
    )])
    .expect("Failed to initialize logging");

    let mut connection = establish_connection();
    connection
        .run_pending_migrations(MIGRATIONS)
        .expect("rocket: Error while running migrations");

    init_db(&mut connection);

    info!("*** starting server ***");

    let figment = rocket::Config::figment()
        .merge(("address", "0.0.0.0"))
        .merge(("port", 5000));

    let server = rocket::custom(figment)
        .register(
            "/",
            catchers![
                not_found_catcher,
                unauthorized_catcher,
                bad_request_catcher,
                unprocessable_entity_catcher,
                internal_server_error_catcher
            ],
        )
        .mount(
            "/api/v1/",
            routes![search_products, create_session, create_user, csrf_token],
        )
        .mount("/", FileServer::from("www"));

    server
}
