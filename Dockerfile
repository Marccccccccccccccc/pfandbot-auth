FROM rust:latest AS builder

WORKDIR /app

RUN rustup default nightly
RUN rustup target add x86_64-unknown-linux-musl
RUN apt-get update && apt-get install -y musl-tools

COPY Cargo.toml Cargo.lock ./

RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release --target x86_64-unknown-linux-musl && rm -f target/x86_64-unknown-linux-musl/release/deps/pfandbot_auth*

COPY . .

RUN cargo build --release --target x86_64-unknown-linux-musl

FROM debian:bookworm-slim

#RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/pfandbot-auth /usr/local/bin/

EXPOSE 3000

ENTRYPOINT ["/usr/local/bin/pfandbot-auth"]
