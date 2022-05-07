#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="adguardhome"
TAG="latest"
DOCKER_PATH="/docker/adguardhome"

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
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/adguardhome/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/adguardhome/conf \
        -v ${DOCKER_PATH}/work:/etc/adguardhome/work \
        -d ${OWNER}/${REPO}:${TAG} \
        --config "/etc/adguardhome/conf/AdGuardHome.yaml" \
        --work-dir "/etc/adguardhome/work" \
        --no-check-update
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
