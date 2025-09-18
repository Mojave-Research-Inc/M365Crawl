FROM rust:1 as builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p auth_broker

FROM gcr.io/distroless/cc
WORKDIR /app
COPY --from=builder /workspace/target/release/auth_broker /app/auth_broker
ENV RUST_LOG=info
EXPOSE 5180
CMD ["/app/auth_broker"]

