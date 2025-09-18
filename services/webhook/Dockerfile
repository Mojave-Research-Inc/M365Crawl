FROM rust:1 as builder
WORKDIR /workspace
COPY . .
RUN cargo build --release -p webhook

FROM gcr.io/distroless/cc
WORKDIR /app
COPY --from=builder /workspace/target/release/webhook /app/webhook
ENV RUST_LOG=info
EXPOSE 8443
CMD ["/app/webhook"]

