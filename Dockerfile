FROM rust:1.97 AS build
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=build /app/target/release/expense-api /app/expense-api
ENV DATABASE_PATH=/app/expense.db
EXPOSE 8080
CMD ["/app/expense-api"]
