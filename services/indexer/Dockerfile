FROM rust:1 as builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p indexer

FROM gcr.io/distroless/cc
WORKDIR /app
COPY --from=builder /workspace/target/release/indexer /app/indexer
ENV RUST_LOG=info
EXPOSE 5200
CMD ["/app/indexer"]

