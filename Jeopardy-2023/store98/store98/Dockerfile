FROM rust:1.68-bullseye as builder

ARG TARGETPLATFORM

WORKDIR /root
RUN --mount=type=cache,target=/usr/local/cargo/registry,id=${TARGETPLATFORM} \
    cargo install cargo-strip

COPY store98/Cargo.* .
COPY store98/src ./src
COPY store98/migrations ./migrations

RUN --mount=type=cache,target=/usr/local/cargo/registry,id=${TARGETPLATFORM} --mount=type=cache,target=/root/target,id=${TARGETPLATFORM} \
    cargo build --release && \
    cargo strip && \
    mv /root/target/release/store98 /root



FROM debian:bullseye-slim

RUN apt update && apt install -y mariadb-client
COPY --from=builder /root/store98 /
COPY store98/www /www

EXPOSE 5000

CMD ["./store98"]