use diesel::prelude::*;
use diesel::r2d2::{ConnectionManager, Pool};
use diesel::sqlite::SqliteConnection;
use serde::{Deserialize, Serialize};

pub type DbPool = Pool<ConnectionManager<SqliteConnection>>;

diesel::table! {
    users (id) {
        id -> Integer,
        name -> Text,
        role -> Text,
        password -> Text,
    }
}

diesel::table! {
    expenses (id) {
        id -> Integer,
        user_id -> Integer,
        title -> Text,
        amount -> Integer,
        card_number -> Text,
        status -> Text,
    }
}

#[derive(Debug, Queryable, Selectable, Serialize)]
#[diesel(table_name = users)]
pub struct User {
    pub id: i32,
    pub name: String,
    pub role: String,
    #[serde(skip)]
    #[allow(dead_code)]
    pub password: String,
}

#[derive(Debug, Queryable, Selectable, QueryableByName, Serialize)]
#[diesel(table_name = expenses)]
pub struct Expense {
    pub id: i32,
    pub user_id: i32,
    pub title: String,
    pub amount: i32,
    pub card_number: String,
    pub status: String,
}

#[derive(Debug, Insertable, Deserialize)]
#[diesel(table_name = expenses)]
pub struct NewExpense {
    #[serde(skip_deserializing)]
    pub user_id: i32,
    pub title: String,
    pub amount: i32,
    pub card_number: String,
    #[serde(skip_deserializing, default = "pending")]
    pub status: String,
}

fn pending() -> String {
    "pending".to_string()
}

pub fn init_pool(path: &str) -> DbPool {
    let manager = ConnectionManager::<SqliteConnection>::new(path);
    let pool = Pool::builder()
        .max_size(4)
        .build(manager)
        .expect("failed to build pool");
    let mut conn = pool.get().expect("failed to get connection");
    migrate_and_seed(&mut conn);
    pool
}

fn migrate_and_seed(conn: &mut SqliteConnection) {
    diesel::sql_query(
        "CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            role TEXT NOT NULL,
            password TEXT NOT NULL
        )",
    )
    .execute(conn)
    .expect("create users");
    diesel::sql_query(
        "CREATE TABLE IF NOT EXISTS expenses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            amount INTEGER NOT NULL,
            card_number TEXT NOT NULL,
            status TEXT NOT NULL
        )",
    )
    .execute(conn)
    .expect("create expenses");

    let count: i64 = users::table.count().get_result(conn).unwrap_or(0);
    if count == 0 {
        diesel::sql_query(
            "INSERT INTO users (name, role, password) VALUES
                ('alice', 'member', 'alice-pass'),
                ('bob', 'member', 'bob-pass'),
                ('carol', 'approver', 'carol-pass')",
        )
        .execute(conn)
        .expect("seed users");
        diesel::sql_query(
            "INSERT INTO expenses (user_id, title, amount, card_number, status) VALUES
                (1, 'タクシー代 渋谷→銀座', 2400, '4111-1111-1111-1111', 'pending'),
                (1, '書籍 Rust入門', 3800, '4111-1111-1111-1111', 'pending'),
                (2, '出張 新幹線 東京→大阪', 14720, '5555-5555-5555-4444', 'pending')",
        )
        .execute(conn)
        .expect("seed expenses");
    }
}
