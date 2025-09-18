FROM rust:1 as builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p gateway

FROM gcr.io/distroless/cc
WORKDIR /app
COPY --from=builder /workspace/target/release/gateway /app/gateway
ENV RUST_LOG=info
EXPOSE 5173
CMD ["/app/gateway"]

