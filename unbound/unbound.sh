#!/bin/bash

# Parameter
OWNER="hezhijie0327" && REDIS_OWNER=""
REPO="unbound" && REDIS_REPO=""
TAG="latest" && REDIS_TAG=""
DOCKER_PATH="/docker/unbound"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

ENABLE_DNSSEC="false"
ENABLE_DNSSEC_PERMISSIVE_MODE="false"

ENABLE_ECS="true"

ENABLE_FORWARD="true"
ENABLE_FORWARD_CACHE="true"
ENABLE_RECURSIVE_DNS="false"

ENABLE_IPV4="true"
ENABLE_IPV6="true"
ENABLE_IP64="false"

ENABLE_LOGFILE="false"

ENABLE_RATELIMIT="false"

CACHE_SIZE_KEY="" # 4m
CACHE_SIZE_MSG="" # 4m
CACHE_SIZE_NEG="" # 1m
CACHE_SIZE_RRSET="" # 4m

CUSTOM_REDIS_LOGICAL_DB="" # 0
CUSTOM_REDIS_SERVER_HOST="" # 127.0.0.1
CUSTOM_REDIS_SERVER_PASSWORD=""
CUSTOM_REDIS_SERVER_PATH=""
CUSTOM_REDIS_SERVER_PORT="" # 6379
ENABLE_REDIS_CACHE="false"

CREATE_REDIS_INSTANCE="false"
REDIS_MAXMEMORY="" # 4MB
REDIS_MAXMEMORY_POLICY="" # noeviction, allkeys-lru, volatile-lru, allkeys-random, volatile-random, volatile-ttl, volatile-lfu, allkeys-lfu

ENABLE_REMOTE_CONTROL="true"

CUSTOM_UPSTREAM="" # 127.0.0.1@5533
ENABLE_TCP_UPSTREAM="false"
ENABLE_TLS_UPSTREAM="false"

HTTPS_PORT="" # 3353
TLS_PORT="" # 3533
UNENCRYPTED_PORT="" # 3553

ENABLE_HTTPS="false"
ENABLE_TLS="false"
ENABLE_UNENCRYPTED_DNS="true"

SSL_CERT="fullchain.cer"
SSL_KEY="zhijie.online.key"

## Function
# Get Latest Image
function GetLatestImage() {
    if [ "${CREATE_REDIS_INSTANCE}" == "true" ]; then
        docker pull ${REDIS_OWNER:-$OWNER}/${REDIS_REPO:-redis}:${REDIS_TAG:-$TAG}
    fi && docker pull ${OWNER}/${REPO}:${TAG} && IMAGES=$(docker images -f "dangling=true" -q)
}
# Cleanup Current Container
function CleanupCurrentContainer() {
    if [ $(docker ps -a --format "table {{.Names}}" | grep -E "^${REPO}$") ]; then
        docker stop ${REPO} && docker rm ${REPO}
    fi

    if [ $(docker ps -a --format "table {{.Names}}" | grep -E "^${REDIS_REPO:-redis}_${REPO}$") ]; then
        docker stop ${REDIS_REPO:-redis}_${REPO} && docker rm ${REPO}_redis
    fi
}
# Download Configuration
function DownloadConfiguration() {
    if [ "${USE_CDN}" == true ]; then
        CDN_PATH="source.zhijie.online"
        ROOT_HINTS_DOMAIN="source.zhijie.online"
        ROOT_HINTS_PATH="CMA_DNS/main/unbound/root.hints"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
        ROOT_HINTS_DOMAIN="www.internic.net"
        ROOT_HINTS_PATH="domain/named.cache"
    fi

    if [ ! -d "${DOCKER_PATH}/conf" ]; then
        mkdir -p "${DOCKER_PATH}/conf"
    fi

    if [ "${DOWNLOAD_CONFIG:-true}" == "true" ]; then
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CMA_DNS/main/unbound/unbound.conf" | sed "s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" > "${DOCKER_PATH}/conf/unbound.conf"

        if [ ! -d "${DOCKER_PATH}/work" ]; then
            mkdir -p "${DOCKER_PATH}/work"
        fi

        if [ "${ENABLE_DNSSEC}" == "false" ]; then
            sed -i "s/validator //g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_DNSSEC}" == "true" ] && [ "${ENABLE_DNSSEC_PERMISSIVE_MODE}" == "true" ]; then
            sed -i "s/val-permissive-mode\: no/val-permissive-mode\: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_ECS}" == "false" ]; then
            sed -i "s/subnetcache //g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_FORWARD}" == "true" ]; then
            sed -i "s/#+/  /g" "${DOCKER_PATH}/conf/unbound.conf"
            if [ "${ENABLE_FORWARD_CACHE}" == "false" ]; then
                sed -i "s/forward-no-cache: no/forward-no-cache: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
        else
            sed -i "/forward-zone:/d;/#+/d" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_RECURSIVE_DNS}" == "true" ]; then
            sed -i "s/forward-first: no/forward-first: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_IPV4}" == "false" ]; then
            sed -i "s/do\-ip4\: yes/do\-ip4\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_IPV6}" == "false" ]; then
            sed -i "s/do\-ip6\: yes/do\-ip6\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_IP64}" == "true" ]; then
            sed -i "s/do\-nat64\: no/do\-nat64\: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_LOGFILE}" == "true" ]; then
            sed -i "s/##/  /g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_RATELIMIT}" == "false" ]; then
            sed -i "s/ratelimit\: 1000/ratelimit\: 0/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${CUSTOM_REDIS_LOGICAL_DB}" != "" ]; then
            sed -i "s/redis-logical-db: 0/redis-logical-db: ${CUSTOM_REDIS_LOGICAL_DB}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_SERVER_HOST}" != "" ]; then
            sed -i "s/redis-server-host: 127.0.0.1/redis-server-host: ${CUSTOM_REDIS_SERVER_HOST}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_SERVER_PASSWORD}" != "" ]; then
            sed -i "s/redis-server-password: ''/redis-server-password: '${CUSTOM_REDIS_SERVER_PASSWORD}'/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_SERVER_PATH}" != "" ]; then
            sed -i "s/redis-server-path: ''/redis-server-path: '${CUSTOM_REDIS_SERVER_PATH}'/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_SERVER_PORT}" != "" ]; then
            sed -i "s/redis-server-port: 6379/redis-server-port: ${CUSTOM_REDIS_SERVER_PORT}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_REDIS_CACHE}" == "false" ]; then
            sed -i "/cachedb:/d;/#-/d;s/cachedb //g" "${DOCKER_PATH}/conf/unbound.conf"
            if [ "${CACHE_SIZE_KEY}" != "" ]; then
                sed -i "s/key-cache-size: 4m/key-cache-size: ${CACHE_SIZE_KEY}/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
            if [ "${CACHE_SIZE_MSG}" != "" ]; then
                sed -i "s/msg-cache-size: 4m/msg-cache-size: ${CACHE_SIZE_MSG}/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
            if [ "${CACHE_SIZE_NEG}" != "" ]; then
                sed -i "s/neg-cache-size: 1m/neg-cache-size: ${CACHE_SIZE_NEG}/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
            if [ "${CACHE_SIZE_RRSET}" != "" ]; then
                sed -i "s/rrset-cache-size: 4m/rrset-cache-size: ${CACHE_SIZE_RRSET}/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
        else
            sed -i "s/#-/  /g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_REMOTE_CONTROL}" == "false" ]; then
            sed -i "/remote-control:/d;/#=/d" "${DOCKER_PATH}/conf/unbound.conf"
        else
            sed -i "s/#=/  /g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${CUSTOM_UPSTREAM}" != "" ]; then
            sed -i "s/127.0.0.1@5533/${CUSTOM_UPSTREAM}/g;s/127.0.0.1@5535/${CUSTOM_UPSTREAM}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_TCP_UPSTREAM}" == "false" ]; then
            sed -i "s/tcp-upstream\: yes/tcp-upstream\: no/g;s/tls-upstream\: no/tls-upstream\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_TLS_UPSTREAM}" == "true" ]; then
            sed -i "s/127.0.0.1@5533/127.0.0.1@5535/g;s/tcp-upstream\: yes/tcp-upstream\: no/g;s/tls-upstream\: no/tls-upstream\: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_UNENCRYPTED_DNS}" == "false" ]; then
            if [ "${ENABLE_HTTPS}" == "true" ] || [ "${ENABLE_TLS}" == "true" ]; then
                sed -i "s/    interface/#+  interface/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
        else
            if [ "${UNENCRYPTED_PORT:-3553}" != "3553" ]; then
                sed "s/port: 3553/port: :${UNENCRYPTED_PORT}/g;s/@3553/@${UNENCRYPTED_PORT}/g" "${DOCKER_PATH}/conf/config.yaml"
            fi
        fi

        if [ "${ENABLE_HTTPS}" == "true" ]; then
            sed -i "s/#@/  /g;s/https-port: 3353/https-port: ${HTTPS_PORT:-3353}/g;s/@3353/@${HTTPS_PORT:-3353}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_TLS}" == "true" ]; then
            sed -i "s/#%/  /g;s/tls-port: 3533/tls-port: ${TLS_PORT:-3533}/g;s/@3533/@${TLS_PORT:-3533}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ -f "${DOCKER_PATH}/conf/unbound.conf" ]; then
            sed -i "/#/d" "${DOCKER_PATH}/conf/unbound.conf"
        fi
    fi

    if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${ROOT_HINTS_DOMAIN}/${ROOT_HINTS_PATH}" > "${DOCKER_PATH}/data/root.hints"
}
# Create New Container
function CreateNewContainer() {
    if [ "${CREATE_REDIS_INSTANCE}" == "true" ]; then
        docker run --name ${REDIS_REPO:-redis}_${REPO} --net host --restart=always \
            -v ${DOCKER_PATH}/data:/etc/redis/data \
            -d ${REDIS_OWNER:-$OWNER}/${REDIS_REPO:-redis}:${REDIS_TAG:-$TAG} \
            --activedefrag yes \
            --aof-use-rdb-preamble yes \
            --appendfsync everysec \
            --appendonly yes \
            --dir /etc/redis/data \
            --lazyfree-lazy-eviction yes \
            --lazyfree-lazy-expire yes \
            --lazyfree-lazy-server-del yes \
            --lazyfree-lazy-user-del yes \
            --lazyfree-lazy-user-flush yes \
            --lfu-decay-time 1 \
            --lfu-log-factor 10 \
            --maxmemory ${REDIS_MAXMEMORY:-4MB} \
            --maxmemory-policy ${REDIS_MAXMEMORY_POLICY:-allkeys-lru} \
            --maxmemory-samples 10 \
            --replica-lazy-flush yes

        docker run -it --rm --entrypoint=/redis-cli --net host \
               ${REDIS_OWNER:-$OWNER}/${REDIS_REPO:-redis}:${REDIS_TAG:-$TAG} \
            info
    fi

    docker run -it --rm --entrypoint=/unbound-anchor \
        -v /etc/resolv.conf:/etc/resolv.conf:ro \
        -v ${DOCKER_PATH}/data:/etc/unbound/data \
           ${OWNER}/${REPO}:${TAG} \
        -a "/etc/unbound/data/root.key" \
        -c "/etc/unbound/data/icannbundle.pem" \
        -f "/etc/resolv.conf" \
        -r "/etc/unbound/data/root.hints" \
        -R

    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/unbound/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/unbound/conf \
        -v ${DOCKER_PATH}/data:/etc/unbound/data \
        -v ${DOCKER_PATH}/work:/etc/unbound/work \
        -d ${OWNER}/${REPO}:${TAG} \
        -c "/etc/unbound/conf/unbound.conf" \
        -d

    if [ "${ENABLE_REMOTE_CONTROL}" == "true" ]; then
        docker run -it --rm --entrypoint=/unbound-control --net host \
            -v ${DOCKER_PATH}/conf:/etc/unbound/conf \
               ${OWNER}/${REPO}:${TAG} \
            -c "/etc/unbound/conf/unbound.conf" \
            -s "127.0.0.1@8953" \
            stats
    fi
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
#Call DownloadConfiguration
DownloadConfiguration
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
