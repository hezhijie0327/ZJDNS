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
    if [ "${USE_CDN}" == true ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi
    ENABLE_HTTPS="false"
    ENABLE_TLS="true"
    SSL_CERT="fullchain.cer"
    SSL_KEY="zhijie.online.key"
    if [ "${ENABLE_HTTPS}" == "true" ]; then
        SED_ENABLE_HTTPS="s/\#\ \ \ \ interface\:\ 0\.0\.0\.0\@5443/\ \ \ \ interface\:\ 0\.0\.0\.0\@5443/g;s/\#\ \ \ \ interface\:\ \:\:\@5443/\ \ \ \ interface\:\ \:\:\@5443/g;"
    fi
    if [ "${ENABLE_TLS}" == "true" ]; then
        SED_ENABLE_TLS="s/\#\ \ \ \ interface\:\ 0\.0\.0\.0\@5853/\ \ \ \ interface\:\ 0\.0\.0\.0\@5853/g;s/\#\ \ \ \ interface\:\ \:\:\@5853/\ \ \ \ interface\:\ \:\:\@5853/g;"
    fi
    curl -s --connect-timeout 15 "https://${CDN_PATH}/CMA_DNS/main/unbound/unbound.conf" | sed "s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g;${SED_ENABLE_HTTPS}${ENABLE_TLS}" > "${DOCKER_PATH}/data/unbound.conf"
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
