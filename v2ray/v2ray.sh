#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="v2ray"
TAG="latest"
DOCKER_PATH="/docker/v2ray"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

RUNNING_MODE="" # client, server

CNIPDB_SOURCE="" # bgp, dbip, geolite2, iana, ip2location, ipipdotnet, iptoasn, vxlink, zjdb

CUSTOM_SERVERNAME="" # demo.zhijie.online
CUSTOM_UUID="" # 99235a6e-05d4-2afe-2990-5bc5cf1f5c52

ENABLE_MUX="" # false, true
MUX_CONCURRENCY=""

ENABLE_WARP="" # false, true

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
    if [ "${RUNNING_MODE}" != "client" ]; then
        RUNNING_MODE="server"
    fi

    if [ "${USE_CDN}" == "true" ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi

    if [ ! -d "${DOCKER_PATH}/conf" ]; then
        mkdir -p "${DOCKER_PATH}/conf"
    fi

    if [ "${DOWNLOAD_CONFIG:-true}" == "true" ]; then
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CMA_DNS/main/v2ray/config_${RUNNING_MODE:-server}.json" > "${DOCKER_PATH}/conf/config.json" && sed -i "s/demo.zhijie.online/${CUSTOM_SERVERNAME:-demo.zhijie.online}/g;s/99235a6e-05d4-2afe-2990-5bc5cf1f5c52/${CUSTOM_UUID:-$(uuidgen | tr 'A-Z' 'a-z')}/g;s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" "${DOCKER_PATH}/conf/config.json"

        if [ "${ENABLE_MUX:-false}" != "false" ]; then
            sed -i 's/"enabled": false/"enabled": true/g' "${DOCKER_PATH}/conf/config.json"

            if [ "${MUX_CONCURRENCY:-8}" != "8" ]; then
                sed -i "s/\"concurrency\": 8,/\"concurrency\": ${MUX_CONCURRENCY},/g" "${DOCKER_PATH}/conf/config.json"
            fi
        fi

        if [ "${ENABLE_WARP:-false}" == "false" ]; then
            sed -i '/"address": "127.0.0.1", "port": 40000/d' "${DOCKER_PATH}/conf/config.json"
        fi
    fi

    if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE:-geolite2}/country_ipv4_6.dat" > "${DOCKER_PATH}/data/geoip.dat"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/v2ray/cert:ro \
        -v /etc/resolv.conf:/etc/resolv.conf:ro \
        -v ${DOCKER_PATH}/conf:/etc/v2ray/conf \
        -v ${DOCKER_PATH}/data:/etc/v2ray/data \
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
