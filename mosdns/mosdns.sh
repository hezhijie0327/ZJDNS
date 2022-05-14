#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="mosdns"
TAG="latest"
DOCKER_PATH="/docker/mosdns"
GHPROXY_URL="https://ghproxy.com/"

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
# Set Proxy Server
function SetProxyServer() {
    export http_proxy="http://127.0.0.1:7890"
    export https_proxy="http://127.0.0.1:7890"
}
# Unset Proxy Server
function UnsetProxyServer() {
    export http_proxy=""
    export https_proxy=""
}
# Update GeoIP CN Rule
function UpdateGeoIPCNRule() {
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/Loyalsoldier/geoip/release/cn.dat" > "${DOCKER_PATH}/data/GeoIP_CN_IPIP.dat"
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CNIPDb/main/cnipdb_combine.txt" > "${DOCKER_PATH}/data/GeoIP_CN_IANA.txt"
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/v2fly/geoip/release/cn.dat" > "${DOCKER_PATH}/data/GeoIP_CN_MaxMind.dat"
}
# Update Suspicious IP Rule
function UpdateSuspiciousIPRule() {
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/POLLUTED.txt" > "${DOCKER_PATH}/data/GeoIP_POLLUTED.txt"
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/RESERVED.txt" > "${DOCKER_PATH}/data/GeoIP_RESERVED.txt"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/mosdns/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/mosdns/conf \
        -v ${DOCKER_PATH}/data:/etc/mosdns/data \
        -d ${OWNER}/${REPO}:${TAG} \
        -c "/etc/mosdns/conf/config.yaml" \
        -dir "/etc/mosdns/data"
}
# Cleanup Expired Image
function CleanupExpiredImage() {
    if [ "${IMAGES}" != "" ]; then
        docker rmi ${IMAGES}
    fi
}

## Process
# Call SetProxyServer
#SetProxyServer
# Call UnsetProxyServer
UnsetProxyServer
# Call GetLatestImage
GetLatestImage
# Call UpdateGeoIPRule
UpdateGeoIPCNRule
# Call UpdateGeoSiteRule
UpdateGeoSiteRule
# Call UpdateSuspiciousIPRule
UpdateSuspiciousIPRule
# Call CleanupCurrentContainer
CleanupCurrentContainer
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
