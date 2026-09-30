FROM rustlang/rust:nightly-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake golang libclang-dev pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /source
COPY . .

RUN cargo build -p boring2 -p boring-sys2 --features boring2/pq-experimental,boring2/prefix-symbols
RUN cargo test -p boring2 -p boring-sys2 --features boring2/pq-experimental,boring2/prefix-symbols --test prefix --test openssl_coexistence
