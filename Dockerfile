FROM rust:1.100-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p natty-relay && cargo build --release --locked -p natty --features cli

FROM scratch AS natty
COPY --from=build /src/target/release/natty /natty
USER 65532:65532
ENTRYPOINT ["/natty"]

FROM scratch AS natty-relay
COPY --from=build /src/target/release/natty-relay /natty-relay
ENTRYPOINT ["/natty-relay"]
