FROM rust:1-bookworm AS build
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY .cargo ./.cargo
COPY .sqlx ./.sqlx
COPY examples ./examples
RUN cargo build --release --workspace --locked

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /etc/nameserver
COPY examples ./examples
COPY resources ./resources
USER 65532:65532

FROM runtime AS resolver
COPY --from=build /src/target/release/nameserver-resolver /usr/local/bin/nameserver-resolver
EXPOSE 5353/udp 5353/tcp 8853/tcp 8443/tcp
ENTRYPOINT ["nameserver-resolver"]
CMD ["--config", "/etc/nameserver/examples/resolver-container.toml"]

FROM runtime AS authority
COPY --from=build /src/target/release/nameserver-authority /usr/local/bin/nameserver-authority
EXPOSE 5354/udp 5354/tcp
ENTRYPOINT ["nameserver-authority"]
CMD ["--config", "/etc/nameserver/examples/authority-container.toml"]

FROM runtime AS control
COPY --from=build /src/target/release/nameserver-control /usr/local/bin/nameserver-control
EXPOSE 8080/tcp
ENTRYPOINT ["nameserver-control"]
CMD ["--config", "/etc/nameserver/examples/control.toml"]

FROM runtime AS cli
COPY --from=build /src/target/release/nameserver /usr/local/bin/nameserver
ENTRYPOINT ["nameserver"]
