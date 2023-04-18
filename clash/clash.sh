#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="clash"
TAG="latest"
DOCKER_PATH="/docker/clash"

CURL_OPTION=""
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
# Update GeoIP CN Rule
function UpdateGeoIPCNRule() {
    CNIPDB_SOURCE="geolite2"
    if [ "${USE_CDN}" == "true" ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi && if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE}/country_ipv4_6.mmdb" > "${DOCKER_PATH}/data/Country.mmdb"
}
# Create New Container
function CreateNewContainer() {

    if [ ! -d "${DOCKER_PATH}/conf" ]; then
        mkdir -p "${DOCKER_PATH}/conf"
    fi

    docker run --name ${REPO} --net host --restart=always \
        -v /etc/resolv.conf:/etc/resolv.conf:ro \
        -v ${DOCKER_PATH}/data:/etc/clash/data \
        -v ${DOCKER_PATH}/conf:/etc/clash/conf \
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
# Call UpdateGeoIPCNRule
UpdateGeoIPCNRule
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
