ARG GOLANG_VERSION="1"

FROM golang:${GOLANG_VERSION} AS build_zjdns

WORKDIR /zjdns

ADD ./* /zjdns

ENV \
    CGO_ENABLED="0"

RUN \
    go build -o zjdns-server -trimpath -ldflags "-s -w -buildid="

FROM scratch

COPY --from=build_zjdns /zjdns/zjdns-server /zjdns-server

EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/zjdns-server"]
