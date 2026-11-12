mod auth;
mod db;
mod handlers;

use actix_cors::Cors;
use actix_web::{middleware::Logger, web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let db_path = std::env::var("DATABASE_PATH").unwrap_or_else(|_| "expense.db".to_string());
    let pool = db::init_pool(&db_path);

    HttpServer::new(move || {
        App::new()
            .app_data(web::Data::new(pool.clone()))
            .wrap(Logger::default())
            .wrap(Cors::permissive())
            .service(handlers::login)
            .service(handlers::list_expenses)
            .service(handlers::search_expenses)
            .service(handlers::create_expense)
            .service(handlers::approve_expense)
            .service(handlers::expense_title)
            .service(handlers::get_expense)
    })
    .bind(("127.0.0.1", 8080))?
    .run()
    .await
}
