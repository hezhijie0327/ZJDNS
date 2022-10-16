#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="mosdns"
TAG="latest"
DOCKER_PATH="/docker/mosdns"
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
# Download mosDNS Configuration
function DownloadmosDNSConfiguration() {
    if [ "${USE_CDN}" == true ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi
    ENABLE_HTTPS="false"
    ENABLE_TLS="false"
    SSL_CERT="fullchain.cer"
    SSL_KEY="zhijie.online.key"
    HTTPS_CONFIG=(
        "      - protocol: https"
        "        addr: ':8443'"
        "        cert: '/etc/mosdns/cert/${SSL_CERT}'"
        "        key: '/etc/mosdns/cert/${SSL_KEY}'"
        "        url_path: '/dns-query'"
    )
    TLS_CONFIG=(
        "      - protocol: tls"
        "        addr: ':8853'"
        "        cert: '/etc/mosdns/cert/${SSL_CERT}'"
        "        key: '/etc/mosdns/cert/${SSL_KEY}'"
    )
    curl -s --connect-timeout 15 "https://${CDN_PATH}/CMA_DNS/main/mosdns/config.yaml" > "${DOCKER_PATH}/conf/config.yaml"
    if [ "${ENABLE_HTTPS}" == "true" ]; then
        for HTTPS_CONFIG_TASK in "${!HTTPS_CONFIG[@]}"; do
            echo "${HTTPS_CONFIG[$HTTPS_CONFIG_TASK]}" >> "${DOCKER_PATH}/conf/config.yaml"
        done
    fi
    if [ "${ENABLE_TLS}" == "true" ]; then
        for TLS_CONFIG_TASK in "${!TLS_CONFIG[@]}"; do
            echo "${TLS_CONFIG[$TLS_CONFIG_TASK]}" >> "${DOCKER_PATH}/conf/config.yaml"
        done
    fi
}
# Update GeoIP CN Rule
function UpdateGeoIPCNRule() {
    CNIPDB_SOURCE="geolite2"
    curl -s --connect-timeout 15 "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE}/country_ipv4_6.dat" > "${DOCKER_PATH}/data/GeoIP_CNIPDb.dat"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/mosdns/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/mosdns/conf \
        -v ${DOCKER_PATH}/data:/etc/mosdns/data \
        -d ${OWNER}/${REPO}:${TAG} \
        start \
        -c "/etc/mosdns/conf/config.yaml" \
        -d "/etc/mosdns/data"
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
# Call DownloadmosDNSConfiguration
DownloadmosDNSConfiguration
# Call UpdateGeoIPRule
UpdateGeoIPCNRule
# Call CleanupCurrentContainer
CleanupCurrentContainer
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
