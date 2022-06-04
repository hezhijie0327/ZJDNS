#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="mosdns"
TAG="latest"
DOCKER_PATH="/docker/mosdns"

## Function
# Get Latest Image
function GetLatestImage() {
    docker pull redis:latest && docker pull ${OWNER}/${REPO}:${TAG} && IMAGES=$(docker images -f "dangling=true" -q)
}
# Cleanup Current Container
function CleanupCurrentContainer() {
    if [ $(docker ps -a --format "table {{.Names}}" | grep -E "^redis$") ]; then
        docker stop redis && docker rm redis
    fi
    if [ $(docker ps -a --format "table {{.Names}}" | grep -E "^${REPO}$") ]; then
        docker stop ${REPO} && docker rm ${REPO}
    fi
}
# Update GeoIP CN Rule
function UpdateGeoIPCNRule() {
    curl -s --connect-timeout 15 "https://source.zhijie.online/CNIPDb/main/cnipdb/country_ipv4_6.txt" > "${DOCKER_PATH}/data/GeoIP_CNIPDb.txt"
}
# Create New Container
function CreateNewContainer() {
    docker run --name redis --net host --restart=always \
        -v ${DOCKER_PATH}/data:/data \
        -d redis:latest \
        --appendonly yes \
        --maxmemory 64m \
        --maxmemory-policy allkeys-lru \
        --maxmemory-samples 10
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
# Call GetLatestImage
GetLatestImage
# Call UpdateGeoIPRule
UpdateGeoIPCNRule
# Call CleanupCurrentContainer
CleanupCurrentContainer
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
