FROM rust:1.83 AS builder

WORKDIR /app
COPY . .

RUN cargo build --release -p reth-eip8141

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/reth-eip8141 /usr/local/bin/reth-eip8141

ENTRYPOINT ["reth-eip8141"]
