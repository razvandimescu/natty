FROM rust:1.94-alpine AS build
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY . .
RUN cargo build --release -p natty-relay

FROM scratch
COPY --from=build /src/target/release/natty-relay /natty-relay
ENTRYPOINT ["/natty-relay"]
