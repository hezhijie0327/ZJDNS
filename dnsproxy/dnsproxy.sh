#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="dnsproxy"
TAG="latest"
DOCKER_PATH="/docker/dnsproxy"

## Function
# Get WAN IP
function GetWANIP() {
    function CheckIPValid() {
        if [ "${Type}" == "A" ]; then
            echo "${IP_RESULT}" | grep -E "^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$"
        else
            echo "${IP_RESULT}" | grep -E "^(([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
        fi
    }
    if [ "${Type}" == "A" ]; then
        IPv4_v6="4"
    else
        IPv4_v6="6"
    fi
    if [ "${StaticIP}" == "auto" ]; then
        IP_RESULT=$(dig -${IPv4_v6:-4} +short TXT @ns1.google.com o-o.myaddr.l.google.com | tr -d '"')
        if [[ $(CheckIPValid) = "" ]]; then
            IP_RESULT=$(dig -${IPv4_v6:-4} +short ANY @resolver1.opendns.com myip.opendns.com)
            if [[ $(CheckIPValid) = "" ]]; then
                IP_RESULT=$(curl -${IPv4_v6:-4} -s --connect-timeout 15 "https://api64.ipify.org")
                if [[ $(CheckIPValid) = "" ]]; then
                    echo "invalid"
                else
                    echo "${IP_RESULT}"
                fi
            else
                echo "${IP_RESULT}"
            fi
        else
            echo "${IP_RESULT}"
        fi
    else
        if [[ $(echo "${StaticIP}" | grep ",") != "" ]]; then
            if [ "${Type}" == "A" ]; then
                IP_RESULT=$(echo "${StaticIP}" | cut -d ',' -f 1)
            else
                IP_RESULT=$(echo "${StaticIP}" | cut -d ',' -f 2)
            fi
            if [[ $(CheckIPValid) = "" ]]; then
                echo "invalid"
            else
                echo "${IP_RESULT}"
            fi
        else
            IP_RESULT="${StaticIP}"
            if [[ $(CheckIPValid) = "" ]]; then
                echo "invalid"
            else
                echo "${IP_RESULT}"
            fi
        fi
    fi
}
# Get Latest Image
function GetLatestImage() {
    docker pull ${OWNER}/${REPO}:${TAG} && IMAGES=$(docker images -f "dangling=true" -q)
}
# Cleanup Current Container
function CleanupCurrentContainer() {
    if [ $(docker ps -a --format "table {{.Names}}" | grep -E "^${REPO}$") ]; then
        docker stop ${REPO} && docker rm ${REPO}
    fi
}
# Create New Container
function CreateNewContainer() {
    LISTEN_IP="" # 0.0.0.0

    UPSTREAM_DNS="" # 127.0.0.1:5533

    CACHE_SIZE="" # 4194304

    EDNS_ADDR="" # auto, 127.0.0.1, ::1
    EDNS_ADDR_TYPE="" # A, AAAA

    HTTPS_PORT="" # 443
    QUIC_PORT="" # 853
    TLS_PORT="" # 853
    UNENCRYPTED_PORT="" # 53

    SSL_CERT="" # fullchain.cer
    SSL_KEY="" # zhijie.online.key

    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/dnsproxy/cert:ro \
        -d ${OWNER}/${REPO}:${TAG} \
        --listen=${LISTEN_IP:-0.0.0.0} \
        --port=${UNENCRYPTED_PORT:-53} \
        --https-port=${HTTPS_PORT:-443} \
        --quic-port=${QUIC_PORT:-853} \
        --tls-port=${TLS_PORT:-853} \
        --tls-crt=/etc/dnsproxy/cert/${SSL_CERT:-fullchain.cer} \
        --tls-key=/etc/dnsproxy/cert/${SSL_KEY:-zhijie.online.key} \
        --tls-max-version=1.3 \
        --tls-min-version=1.2 \
        --fallback=tls://223.5.5.5:853 \
        --fallback=tls://223.6.6.6:853 \
        --fallback=tls://[2400:3200::1]:853 \
        --fallback=tls://[2400:3200:baba::1]:853 \
        --upstream=${UPSTREAM_DNS:-127.0.0.1:5533} \
        --cache \
        --cache-size=${CACHE_SIZE:-4194304} \
        --cache-max-ttl=86400 \
        --cache-min-ttl=0 \
        --cache-optimistic \
        --edns-addr=$(StaticIP="${EDNS_ADDR:-auto}" && Type="${EDNS_ADDR_TYPE:-A}" && GetWANIP) \
        --edns \
        --http3 \
        --insecure \
        --ratelimit=1000 \
        --refuse-any \
        --timeout=5s
}
# Cleanup Expired Image
function CleanupExpiredImage() {
    if [ "${IMAGES}" != "" ]; then
        docker rmi ${IMAGES}
    fi
}

## Process
# Call GetLatestImage
GetLatestImage
# Call CleanupCurrentContainer
CleanupCurrentContainer
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
