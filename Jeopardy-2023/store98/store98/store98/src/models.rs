use std::io::Write;

use diesel;
use diesel::backend::{Backend, RawValue};
use diesel::deserialize::FromSql;
use diesel::mysql::Mysql;
use diesel::prelude::{
    AsChangeset, Identifiable, Insertable, Queryable, QueryableByName, Selectable
};
use diesel::serialize::{IsNull, Output, ToSql};
use diesel::sql_types::Text;
use diesel::{deserialize, serialize, AsExpression, FromSqlRow};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use uuid;

use crate::schema::{products, users, csrftokens};

#[derive(Debug, Clone, Copy, AsExpression, FromSqlRow, PartialEq, Eq, Hash, Default)]
#[diesel(sql_type = Text)]
pub struct Uuid {
    uuid: uuid::Uuid,
}

impl<'de> Deserialize<'de> for Uuid {
    fn deserialize<D>(deserializer: D) -> Result<Uuid, D::Error>
    where
        D: Deserializer<'de>,
    {
        let buf = String::deserialize(deserializer)?;

        Ok(Uuid::new(uuid::Uuid::try_parse(&buf).map_err(|err| {
            serde::de::Error::custom(&format!("{}", err))
        })?))
    }
}

impl Serialize for Uuid {
    fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&self.inner().to_string())
    }
}

impl Uuid {
    pub fn new(uuid: uuid::Uuid) -> Self {
        Self { uuid }
    }

    pub fn inner(&self) -> &uuid::Uuid {
        &self.uuid
    }
}

impl ToSql<Text, Mysql> for Uuid
where
    String: ToSql<Text, Mysql>,
{
    fn to_sql<'b>(&'b self, out: &mut Output<'b, '_, Mysql>) -> serialize::Result {
        out.write_all(self.inner().to_string().as_bytes())?;
        Ok(IsNull::No)
    }
}

impl<DB> FromSql<Text, DB> for Uuid
where
    DB: Backend,
    *const str: FromSql<Text, DB>,
{
    fn from_sql(bytes: RawValue<DB>) -> deserialize::Result<Self> {
        let s: *const str = FromSql::<Text, DB>::from_sql(bytes)?;

        unsafe {
            match uuid::Uuid::try_parse(&*s) {
                Ok(u) => Ok(Uuid::new(u)),
                Err(_) => Err(format!("Invalid uuid {}", &*s).into()),
            }
        }
    }
}

// Models

#[derive(
    Selectable, Queryable, QueryableByName, Identifiable, Debug, PartialEq
)]
#[diesel(primary_key(id))]
#[diesel(table_name = csrftokens)]
pub struct CsrfToken {
    pub id: i32,
    pub token: String,
}

#[derive(Insertable)]
#[diesel(table_name = csrftokens)]
pub struct NewCsrfToken {
    pub token: String,
}

impl NewCsrfToken {
    pub fn new(token: String) -> Self {
        Self { token: token }
    }

    pub fn inner(&self) -> &String {
        &self.token
    }
}

#[derive(
    Serialize, Queryable, QueryableByName, Selectable, Identifiable, Debug, PartialEq, AsChangeset,
)]
#[diesel(primary_key(id))]
#[diesel(table_name = products)]
#[serde(rename_all = "camelCase")]
pub struct Product {
    pub id: i32,
    pub price: i32,
    pub name: String,
    pub description: String,
    pub image_src: String,
    pub image_credits: String,
}

#[derive(
    Clone, Queryable, QueryableByName, Selectable, Identifiable, Debug, PartialEq, AsChangeset,
)]
#[diesel(primary_key(id))]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub username: String,
    pub password: String,
    pub token: Option<Uuid>,
}

#[derive(
    Serialize,
    Deserialize,
    Insertable,
    Queryable,
    QueryableByName,
    Selectable,
    Debug,
    PartialEq,
    AsChangeset,
)]
#[diesel(table_name = users)]
pub struct UserRequest {
    pub username: String,
    pub password: String,
    #[serde(skip_deserializing, default)]
    pub token: Option<Uuid>,
}
