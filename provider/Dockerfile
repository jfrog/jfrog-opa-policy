FROM alpine:3.23.2 AS builder

RUN apk update --no-cache && apk add --no-cache go make

WORKDIR /tmp/provider

# Setup cache
RUN go env -w GOCACHE=/go-cache
RUN go env -w GOMODCACHE=/gomod-cache

COPY . .
RUN --mount=type=cache,target=/gomod-cache --mount=type=cache,target=/go-cache GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o main .

 # v3.21.3
FROM alpine:3.23.2

WORKDIR /
COPY --from=builder /tmp/provider/main .

EXPOSE 8443
USER 1000:1000
ENTRYPOINT ["./main"]
