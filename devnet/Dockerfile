# Build the exact repository-pinned toolchain in Linux, including on a macOS host.
FROM rust:1.97.1-bookworm@sha256:0e2bcaef56d041a486784e54104a81aebe0da44bd03019bd70bc0401e42e4a97 AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY specs ./specs
COPY tests ./tests
COPY examples ./examples
RUN cargo test -p naome-cli -p naome-validator -p naome-verifier --profile release --all-targets --all-features --locked --no-run

FROM ubuntu:24.04@sha256:224a1869083a311ef3f13648a154ba79832fbef6364d31493642ca03082da254
RUN apt-get update && apt-get install -y --no-install-recommends python3 ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /build/target/release/naome-validator /build/target/release/naome /build/target/release/naome-verifier /usr/local/bin/
COPY devnet/state_agent.py devnet/proxy.py /opt/naome/devnet/
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
CMD ["naome-validator", "--help"]
