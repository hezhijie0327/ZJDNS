ARG GOLANG_VERSION="1"

FROM golang:${GOLANG_VERSION} AS build_zjdns

WORKDIR /zjdns

ADD ./* /zjdns

ENV \
    CGO_ENABLED="0"

RUN \
    wget "https://curl.se/ca/cacert.pem" \
    && go mod tidy \
    && go build -o zjdns -trimpath -ldflags "-s -w -buildid="

FROM scratch AS rebase_zjdns

COPY --from=build_zjdns /zjdns/cacert.pem /etc/ssl/certs/ca-certificates.crt
COPY --from=build_zjdns /zjdns/zjdns /zjdns

FROM scratch

COPY --from=rebase_zjdns / /

EXPOSE 53/tcp 53/udp 853/tcp 853/udp

ENTRYPOINT ["/zjdns"]
