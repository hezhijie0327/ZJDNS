ARG GOLANG_VERSION="1"

FROM golang:${GOLANG_VERSION} AS build_zjdns

WORKDIR /zjdns

ADD ./* /zjdns

ENV \
    CGO_ENABLED="0"

RUN \
    go mod tidy \
    && go build -o zjdns -trimpath -ldflags "-s -w -buildid="

FROM scratch

COPY --from=build_zjdns /zjdns/zjdns /zjdns

EXPOSE 53/tcp 53/udp

ENTRYPOINT ["/zjdns"]
