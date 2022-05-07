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
# Update GeoIP & GeoSite Rule
function UpdateGeoIPSiteRule() {
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geoip.dat" > "${DOCKER_PATH}/config/geoip.dat"
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/Loyalsoldier/v2ray-rules-dat/release/geosite.dat" > "${DOCKER_PATH}/config/geosite.dat"
}
# Update GFWList2AGH Rule
function UpdateGFWList2AGHRule() {
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/GFWList2AGH/main/gfwlist2domain/blacklist_full.txt" > "${DOCKER_PATH}/config/GFWList2AGH_blacklist_full.txt"
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/GFWList2AGH/main/gfwlist2domain/whitelist_full.txt" > "${DOCKER_PATH}/config/GFWList2AGH_whitelist_full.txt"
}
# Update CNIPDB Rule
function UpdateCNIPDBRule() {
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CNIPDb/main/cnipdb_combine.txt" > "${DOCKER_PATH}/config/CNIPDB.txt"
}
# Update Reserved IP Rule
function UpdateReservedIPRule() {
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/reserved_ipv4.txt" > "${DOCKER_PATH}/config/reserved_ipv4.txt"
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/reserved_ipv6.txt" > "${DOCKER_PATH}/config/reserved_ipv6.txt"
}
# Update GFW Polluted IP Rule
function UpdateGFWPollutedIPRule() {
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/gfw_polluted_ipv4.txt" > "${DOCKER_PATH}/config/gfw_polluted_ipv4.txt"
    curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/gfw_polluted_ipv6.txt" > "${DOCKER_PATH}/config/gfw_polluted_ipv6.txt"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/mosdns/cert:ro \
        -v ${DOCKER_PATH}/config:/etc/mosdns/conf \
        -d ${OWNER}/${REPO}:${TAG} \
        -dir /etc/mosdns/conf
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
# Call UpdateGeoIPSiteRule
UpdateGeoIPSiteRule
# Call UpdateGFWList2AGHRule
UpdateGFWList2AGHRule
# Call UpdateCNIPDBRule
UpdateCNIPDBRule
# Call UpdateReservedIPRule
UpdateReservedIPRule
# Call UpdateGFWPollutedIPRule
UpdateGFWPollutedIPRule
# Call CleanupCurrentContainer
CleanupCurrentContainer
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
