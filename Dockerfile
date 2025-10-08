ARG GOLANG_VERSION="1"

FROM golang:${GOLANG_VERSION} AS build_zjdns

WORKDIR /zjdns

ADD ./* /zjdns

ENV \
    CGO_ENABLED="0"

RUN \
    wget "https://curl.se/ca/cacert.pem" \
    && go mod tidy \
    && COMMIT_SHA=$(git rev-parse --short HEAD 2>/dev/null || echo "unknown") \
    && BUILD_TIME=$(date -u '+%Y-%m-%d %H:%M:%S UTC') \
    && go build -o zjdns -trimpath -ldflags "-s -w -buildid= -X main.CommitHash=${COMMIT_SHA} -X main.BuildTime=${BUILD_TIME}"

FROM scratch AS rebase_zjdns

COPY --from=build_zjdns /zjdns/cacert.pem /etc/ssl/certs/ca-certificates.crt
COPY --from=build_zjdns /zjdns/zjdns /zjdns

FROM scratch

COPY --from=rebase_zjdns / /

EXPOSE 53/tcp 53/udp 443/tcp 443/udp 853/tcp 853/udp

ENTRYPOINT ["/zjdns"]
