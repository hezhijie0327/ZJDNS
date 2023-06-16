#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="caddy"
TAG="latest"
DOCKER_PATH="/docker/caddy"

CURL_OPTION=""
USE_CDN="true"

SSL_CERT="fullchain.cer"
SSL_KEY="zhijie.online.key"

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
# Download Configuration
function DownloadConfiguration() {
    if [ "${USE_CDN}" == "true" ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi
    if [ ! -d "${DOCKER_PATH}/conf" ]; then
        mkdir -p "${DOCKER_PATH}/conf"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CMA_DNS/main/caddy/Caddyfile" > "${DOCKER_PATH}/conf/Caddyfile" && sed -i "s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" "${DOCKER_PATH}/conf/Caddyfile"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/caddy/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/caddy/conf \
        -d ${OWNER}/${REPO}:${TAG} \
        run \
        --config /etc/caddy/conf/Caddyfile
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
