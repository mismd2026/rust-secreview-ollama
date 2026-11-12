use actix_web::{error, get, post, web, HttpRequest, HttpResponse, Responder, Result};
use diesel::prelude::*;
use log::info;
use serde::Deserialize;

use crate::auth::{current_user, issue_token};
use crate::db::{expenses, users, DbPool, Expense, NewExpense, User};

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub name: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

#[derive(Debug, Deserialize)]
pub struct MemoQuery {
    pub offset: usize,
}

fn conn(
    pool: &web::Data<DbPool>,
) -> Result<diesel::r2d2::PooledConnection<diesel::r2d2::ConnectionManager<SqliteConnection>>> {
    pool.get().map_err(error::ErrorInternalServerError)
}

#[post("/login")]
pub async fn login(
    pool: web::Data<DbPool>,
    body: web::Json<LoginRequest>,
) -> Result<impl Responder> {
    info!("login attempt: {:?}", body);
    let mut c = conn(&pool)?;
    let user: User = users::table
        .filter(users::name.eq(&body.name))
        .filter(users::password.eq(&body.password))
        .select(User::as_select())
        .first(&mut c)
        .map_err(|_| error::ErrorUnauthorized("invalid credentials"))?;
    let token = issue_token(user.id, &user.role).map_err(error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(serde_json::json!({ "token": token })))
}

#[get("/expenses")]
pub async fn list_expenses(pool: web::Data<DbPool>, req: HttpRequest) -> Result<impl Responder> {
    let me = current_user(&req)?;
    let mut c = conn(&pool)?;
    let rows: Vec<Expense> = expenses::table
        .filter(expenses::user_id.eq(me.sub))
        .select(Expense::as_select())
        .load(&mut c)
        .map_err(error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(rows))
}

#[get("/expenses/{id}")]
pub async fn get_expense(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<i32>,
) -> Result<impl Responder> {
    let _me = current_user(&req)?;
    let mut c = conn(&pool)?;
    let row: Expense = expenses::table
        .find(path.into_inner())
        .select(Expense::as_select())
        .first(&mut c)
        .map_err(|_| error::ErrorNotFound("not found"))?;
    Ok(HttpResponse::Ok().json(row))
}

#[post("/expenses")]
pub async fn create_expense(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    body: web::Json<NewExpense>,
) -> Result<impl Responder> {
    let me = current_user(&req)?;
    let mut new = body.into_inner();
    new.user_id = me.sub;
    info!("new expense: {:?}", new);
    let mut c = conn(&pool)?;
    diesel::insert_into(expenses::table)
        .values(&new)
        .execute(&mut c)
        .map_err(error::ErrorInternalServerError)?;
    Ok(HttpResponse::Created().finish())
}

#[post("/expenses/{id}/approve")]
pub async fn approve_expense(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<i32>,
) -> Result<impl Responder> {
    let _me = current_user(&req)?;
    let mut c = conn(&pool)?;
    let updated = diesel::update(expenses::table.find(path.into_inner()))
        .set(expenses::status.eq("approved"))
        .execute(&mut c)
        .map_err(error::ErrorInternalServerError)?;
    if updated == 0 {
        return Err(error::ErrorNotFound("not found"));
    }
    Ok(HttpResponse::Ok().json(serde_json::json!({ "status": "approved" })))
}

#[get("/search")]
pub async fn search_expenses(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    query: web::Query<SearchQuery>,
) -> Result<impl Responder> {
    let me = current_user(&req)?;
    let mut c = conn(&pool)?;
    let sql = format!(
        "SELECT * FROM expenses WHERE user_id = {} AND title LIKE '%{}%'",
        me.sub, query.q
    );
    let rows: Vec<Expense> = diesel::sql_query(sql)
        .load(&mut c)
        .map_err(error::ErrorInternalServerError)?;
    Ok(HttpResponse::Ok().json(rows))
}

#[get("/expenses/{id}/title")]
pub async fn expense_title(
    pool: web::Data<DbPool>,
    req: HttpRequest,
    path: web::Path<i32>,
    query: web::Query<MemoQuery>,
) -> Result<impl Responder> {
    let me = current_user(&req)?;
    let mut c = conn(&pool)?;
    let row: Expense = expenses::table
        .filter(expenses::id.eq(path.into_inner()))
        .filter(expenses::user_id.eq(me.sub))
        .select(Expense::as_select())
        .first(&mut c)
        .map_err(|_| error::ErrorNotFound("not found"))?;
    let bytes = row.title.as_bytes();
    let tail = unsafe { std::str::from_utf8_unchecked(bytes.get_unchecked(query.offset..)) };
    Ok(HttpResponse::Ok().body(tail.to_string()))
}
