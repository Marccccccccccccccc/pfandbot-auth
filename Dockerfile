FROM rust:1.76 as builder

WORKDIR /app

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release && rm -f target/release/deps/pfandbot_auth*

COPY . .

RUN cargo build --release

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/pfandbot-auth /usr/local/bin/

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/pfandbot-auth"]
