FROM rust:1 as builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p orchestrator

FROM gcr.io/distroless/cc
WORKDIR /app
COPY --from=builder /workspace/target/release/orchestrator /app/orchestrator
ENV RUST_LOG=info
EXPOSE 5210
CMD ["/app/orchestrator"]

