#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="v2ray"
TAG="latest"
DOCKER_PATH="/docker/v2ray"

CURL_OPTION=""
USE_CDN="true"

CUSTOM_DOMAIN="" # demo.zhijie.online
CUSTOM_UUID="" # 99235a6e-05d4-2afe-2990-5bc5cf1f5c52

ENABLE_WARP="false"

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
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CMA_DNS/main/v2ray/config.json" > "${DOCKER_PATH}/conf/config.json" && sed -i "s/demo.zhijie.online/${CUSTOM_DOMAIN:-demo.zhijie.online}/g;s/99235a6e-05d4-2afe-2990-5bc5cf1f5c52/${CUSTOM_UUID:-$(uuidgen | tr 'A-Z' 'a-z')}/g;s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" "${DOCKER_PATH}/conf/config.json"

    if [ "${ENABLE_WARP}" == "true" ]; then
        sed -i "s/\\/\\/##/    /g" "${DOCKER_PATH}/conf/config.json"
    fi

    if [ -f "${DOCKER_PATH}/conf/config.json" ]; then
        sed -i "/\\/\\/#/d" "${DOCKER_PATH}/conf/config.json"
    fi
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/v2ray/cert:ro \
        -v /etc/resolv.conf:/etc/resolv.conf:ro \
        -v ${DOCKER_PATH}/conf:/etc/v2ray/conf \
        -d ${OWNER}/${REPO}:${TAG} \
        run \
        -c /etc/v2ray/conf/config.json
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
# Call DownloadConfiguration
DownloadConfiguration
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
