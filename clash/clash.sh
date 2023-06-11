#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="clash"
TAG="latest" # latest, meta
DOCKER_PATH="/docker/clash"

CURL_OPTION=""
USE_CDN="true"

CNIPDB_SOURCE="" # bgp, dbip, geolite2, iana, ip2location, ipipdotnet, iptoasn, vxlink, zjdb

CUSTOM_SERVER="" # demo.zhijie.online
CUSTOM_SERVERNAME="" # demo.zhijie.online
CUSTOM_UUID="" # 99235a6e-05d4-2afe-2990-5bc5cf1f5c52

ENABLE_VLESS="false"

## Function
# Get Latest Image
function GetLatestImage() {
    if [ "${ENABLE_VLESS}" == "true" ]; then
        TAG="meta"
    fi && docker pull ${OWNER}/${REPO}:${TAG} && IMAGES=$(docker images -f "dangling=true" -q)
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
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CMA_DNS/main/clash/config.yaml" > "${DOCKER_PATH}/conf/config.yaml" && sed -i "s/server: demo.zhijie.online/server: ${CUSTOM_SERVER:-demo.zhijie.online}/g;s/Host: demo.zhijie.online/Host: ${CUSTOM_SERVERNAME:-${CUSTOM_SERVER:-demo.zhijie.online}}/g;s/99235a6e-05d4-2afe-2990-5bc5cf1f5c52/${CUSTOM_UUID:-$(uuidgen | tr 'A-Z' 'a-z')}/g" "${DOCKER_PATH}/conf/config.yaml"

    if [ "${ENABLE_VLESS}" == "true" ]; then
        sed -i "s/alterId: 0, cipher: auto, //g;s/vmess/vless/g;s/443/8443/g" "${DOCKER_PATH}/conf/config.yaml"
    fi

    if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE:-geolite2}/country_ipv4_6.mmdb" > "${DOCKER_PATH}/data/Country.mmdb"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /etc/resolv.conf:/etc/resolv.conf:ro \
        -v ${DOCKER_PATH}/conf:/etc/clash/conf \
        -v ${DOCKER_PATH}/data:/etc/clash/data \
        -d ${OWNER}/${REPO}:${TAG} \
        -d "/etc/clash/data" \
        -f "/etc/clash/conf/config.yaml"
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
