FROM rust:1 as builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p connectors

FROM gcr.io/distroless/cc
WORKDIR /app
COPY --from=builder /workspace/target/release/connectors /app/connectors
ENV RUST_LOG=info
EXPOSE 5190
CMD ["/app/connectors"]

