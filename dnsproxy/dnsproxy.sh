#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="dnsproxy"
TAG="latest"
DOCKER_PATH="/docker/dnsproxy"

LISTEN_IP="" # 0.0.0.0

RUNNING_MODE="" # all-servers, fastest-addr

BOOTSTRAP_DNS=()
FALLBACK_DNS=()
UPSTREAM_DNS=() # 127.0.0.1:5533

ENABLE_CACHE="true"
CACHE_SIZE="" # 4194304

ENABLE_EDNS="false"
EDNS_ADDR="" # auto, 127.0.0.1, ::1
EDNS_ADDR_TYPE="" # A, AAAA

HTTPS_PORT="" # 3335
QUIC_PORT="" # 3555
TLS_PORT="" # 3555
UNENCRYPTED_PORT="" # 3355

ENABLE_HTTP3="false"
ENABLE_HTTPS="false"
ENABLE_QUIC="false"
ENABLE_TLS="false"
ENABLE_UNENCRYPTED_DNS="true"

SSL_CERT="" # fullchain.cer
SSL_KEY="" # zhijie.online.key

## Function
# Get WAN IP
function GetWANIP() {
    if [ "${Type}" == "A" ]; then
        IPv4_v6="4"
        IP_REGEX="^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$"
    else
        IPv4_v6="6"
        IP_REGEX="^(([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    fi
    if [ "${StaticIP:-auto}" == "auto" ]; then
        IP_RESULT=$(curl -${IPv4_v6:-4} -s --connect-timeout 15 "https://api.cloudflare.com/cdn-cgi/trace" | grep "ip=" | sed "s/ip=//g" | grep -E "${IP_REGEX}")
        if [ "${IP_RESULT}" == "" ]; then
            IP_RESULT=$(curl -${IPv4_v6:-4} -s --connect-timeout 15 "https://api64.ipify.org" | grep -E "${IP_REGEX}")
            if [ "${IP_RESULT}" == "" ]; then
                IP_RESULT=$(dig -${IPv4_v6:-4} +short TXT @ns1.google.com o-o.myaddr.l.google.com | tr -d '"' | grep -E "${IP_REGEX}")
                if [ "${IP_RESULT}" == "" ]; then
                    IP_RESULT=$(dig -${IPv4_v6:-4} +short ANY @resolver1.opendns.com myip.opendns.com | grep -E "${IP_REGEX}")
                    if [ "${IP_RESULT}" == "" ]; then
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
            echo "${IP_RESULT}"
        fi
    else
        if [ "$(echo ${StaticIP} | grep ',')" != "" ]; then
            if [ "${Type}" == "A" ]; then
                IP_RESULT=$(echo "${StaticIP}" | cut -d ',' -f 1 | grep -E "${IP_REGEX}")
            else
                IP_RESULT=$(echo "${StaticIP}" | cut -d ',' -f 2 | grep -E "${IP_REGEX}")
            fi
            if [ "${IP_RESULT}" == "" ]; then
                echo "invalid"
            else
                echo "${IP_RESULT}"
            fi
        else
            IP_RESULT=$(echo "${StaticIP}" | grep -E "${IP_REGEX}")
            if [ "${IP_RESULT}" == "" ]; then
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
    RUNTIME_CONFIG=(
        "--listen=${LISTEN_IP:-0.0.0.0}"
        "--insecure"
        "--ratelimit=1000"
        "--refuse-any"
        "--timeout=5s"
    )

    for BOOTSTRAP_DNS_TASK in "${!BOOTSTRAP_DNS[@]}"; do
        RUNTIME_CONFIG+=("--bootstrap=${BOOTSTRAP_DNS[$BOOTSTRAP_DNS_TASK]}")
    done

    for FALLBACK_DNS_TASK in "${!FALLBACK_DNS[@]}"; do
        RUNTIME_CONFIG+=("--fallback=${FALLBACK_DNS[$FALLBACK_DNS_TASK]}")
    done

    for UPSTREAM_DNS_TASK in "${!UPSTREAM_DNS[@]}"; do
        RUNTIME_CONFIG+=("--upstream=${UPSTREAM_DNS[$UPSTREAM_DNS_TASK]}")
    done

    if [ "${RUNNING_MODE}" == "all-servers" ]; then
        RUNTIME_CONFIG+=("--all-servers")
    elif [ "${RUNNING_MODE}" == "fastest-addr" ]; then
        RUNTIME_CONFIG+=("--fastest-addr")
    fi

    if [ "${ENABLE_CACHE}" == "true" ]; then
        RUNTIME_CONFIG+=("--cache" "--cache-size=${CACHE_SIZE:-4194304}" "--cache-max-ttl=86400" "--cache-min-ttl=0" "--cache-optimistic")
    fi

    if [ "${ENABLE_EDNS}" == "true" ]; then
        RUNTIME_CONFIG+=("--edns" "--edns-addr=$(StaticIP=${EDNS_ADDR} && Type=${EDNS_ADDR_TYPE:-A} && GetWANIP)")
    fi

    if [ "${ENABLE_UNENCRYPTED_DNS}" == "false" ]; then
        if [ "${ENABLE_HTTPS}" == "false" ] && [ "${ENABLE_TLS}" == "false" ]; then
            RUNTIME_CONFIG+=("--port=${UNENCRYPTED_PORT:-3355}")
        fi
    else
        RUNTIME_CONFIG+=("--port=${UNENCRYPTED_PORT:-3355}")
    fi

    if [ "${ENABLE_HTTP3}" == "true" ]; then
        RUNTIME_CONFIG+=("--http3")
    fi
    if [ "${ENABLE_HTTPS}" == "true" ] || [ "${ENABLE_HTTP3}" == "true" ]; then
        RUNTIME_CONFIG+=("--https-port=${HTTPS_PORT:-3335}")
    fi
    if [ "${ENABLE_QUIC}" == "true" ]; then
        RUNTIME_CONFIG+=("--quic-port=${QUIC_PORT:-3555}")
    fi
    if [ "${ENABLE_TLS}" == "true" ]; then
        RUNTIME_CONFIG+=("--tls-port=${TLS_PORT:-3335}")
    fi
    if [ "${ENABLE_HTTPS}" == "true" ] || [ "${ENABLE_QUIC}" == "true" ] || [ "${ENABLE_TLS}" == "true" ]; then
        RUNTIME_CONFIG+=("--tls-crt=/etc/dnsproxy/cert/${SSL_CERT:-fullchain.cer}" "--tls-key=/etc/dnsproxy/cert/${SSL_KEY:-zhijie.online.key}")
    fi

    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/dnsproxy/cert:ro \
        -d ${OWNER}/${REPO}:${TAG} ${RUNTIME_CONFIG[*]}
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
