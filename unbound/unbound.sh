#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="unbound"
TAG="latest"
DOCKER_PATH="/docker/unbound"
USE_CDN="true"

## Function
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
# Download Unbound Configuration
function DownloadUnboundConfiguration() {
    ENABLE_CACHE="true"
    ENABLE_DNSSEC="false"
    ENABLE_ECS="true"
    ENABLE_RECURSIVE_DNS="false"
    ENABLE_REDIS_CACHE="false"

    ENABLE_LOGFILE="false"

    ENABLE_RATELIMIT="false"

    ENABLE_TCP_UPSTREAM="false"
    ENABLE_TLS_UPSTREAM="false"

    ENABLE_HTTPS="false"
    ENABLE_TLS="false"
    ENABLE_UNENCRYPTED_DNS="true"
    SSL_CERT="fullchain.cer"
    SSL_KEY="zhijie.online.key"

    if [ "${USE_CDN}" == true ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi && curl -s --connect-timeout 15 "https://${CDN_PATH}/CMA_DNS/main/unbound/unbound.conf" | sed "s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" > "${DOCKER_PATH}/data/unbound.conf"

    if [ "${ENABLE_CACHE}" == "false" ]; then
        sed -i "s/forward-no-cache: no/forward-no-cache: yes/g" "${DOCKER_PATH}/data/unbound.conf"
    fi
    if [ "${ENABLE_DNSSEC}" == "false" ]; then
        sed -i "s/validator //g" "${DOCKER_PATH}/data/unbound.conf"
    fi
    if [ "${ENABLE_ECS}" == "false" ]; then
        sed -i "s/subnetcache //g" "${DOCKER_PATH}/data/unbound.conf"
    fi
    if [ "${ENABLE_RECURSIVE_DNS}" == "true" ]; then
        sed -i "s/forward-first: no/forward-first: yes/g" "${DOCKER_PATH}/data/unbound.conf"
    fi
    if [ "${ENABLE_REDIS_CACHE}" == "false" ]; then
        sed -i "s/cachedb //g" "${DOCKER_PATH}/data/unbound.conf"
    fi

    if [ "${ENABLE_LOGFILE}" == "true" ]; then
        sed -i "s/##/  /g" "${DOCKER_PATH}/data/unbound.conf"
    fi

    if [ "${ENABLE_RATELIMIT}" == "false" ]; then
        sed -i "s/ratelimit\: 1000/ratelimit\: 0/g" "${DOCKER_PATH}/data/unbound.conf"
    fi

    if [ "${ENABLE_TCP_UPSTREAM}" == "false" ]; then
        sed -i "s/forward-tcp-upstream\: yes/forward-tcp-upstream\: no/g;s/forward-tls-upstream\: no/forward-tls-upstream\: no/g" "${DOCKER_PATH}/data/unbound.conf"
    fi
    if [ "${ENABLE_TLS_UPSTREAM}" == "true" ]; then
        sed -i "s/@5533/@5535/g;s/forward-tcp-upstream\: yes/forward-tcp-upstream\: no/g;s/forward-tls-upstream\: no/forward-tls-upstream\: yes/g" "${DOCKER_PATH}/data/unbound.conf"
    fi

    if [ "${ENABLE_UNENCRYPTED_DNS}" == "false" ]; then
        if [ "${ENABLE_HTTPS}" == "true" ] || [ "${ENABLE_TLS}" == "true" ]; then
            sed -i "s/    interface/#+  interface/g" "${DOCKER_PATH}/data/unbound.conf"
        fi
    fi

    if [ "${ENABLE_HTTPS}" == "true" ]; then
        sed -i "s/#@/  /g" "${DOCKER_PATH}/data/unbound.conf"
    fi
    if [ "${ENABLE_TLS}" == "true" ]; then
        sed -i "s/#%/  /g" "${DOCKER_PATH}/data/unbound.conf"
    fi
}
# Update Root Hints
function UpdateRootHints() {
    curl -s --connect-timeout 15 "https://www.internic.net/domain/named.cache" > "${DOCKER_PATH}/data/root.hints"
}
# Create New Container
function CreateNewContainer() {
    docker run -it --rm --entrypoint=/unbound-anchor \
        -v ${DOCKER_PATH}/data:/usr/local/etc/unbound \
           ${OWNER}/${REPO}:${TAG}
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/usr/local/etc/ssl:ro \
        -v ${DOCKER_PATH}/data:/usr/local/etc/unbound \
        -d ${OWNER}/${REPO}:${TAG} \
        -c "/usr/local/etc/unbound/unbound.conf" \
        -d
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
#Call DownloadUnboundConfiguration
DownloadUnboundConfiguration
# Call UpdateRootHints
UpdateRootHints
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
