# Stage 1: builder
FROM golang:alpine AS builder

ARG GIT_COMMIT=unknown

WORKDIR /src
COPY ./src .

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w -X main.gBuildCommit=${GIT_COMMIT}" \
    -o /tmp/open-filerep .

# Stage 2: runtime
FROM alpine

RUN apk add --no-cache ca-certificates

COPY --from=builder /tmp/open-filerep /usr/local/bin/open-filerep

RUN mkdir /data && chown 1000 /data

USER 1000

EXPOSE 8080

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/open-filerep", "--db", "/data", "--port", ":8080"]
