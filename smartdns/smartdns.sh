#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="smartdns"
TAG="latest"
DOCKER_PATH="/docker/smartdns"

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
    if [ ! -d "${DOCKER_PATH}/conf" ]; then
        mkdir -p "${DOCKER_PATH}/conf"
    fi

    if [ ! -d "${DOCKER_PATH}/work" ]; then
        mkdir -p "${DOCKER_PATH}/work"
    fi

    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/smartdns/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/smartdns/conf \
        -v ${DOCKER_PATH}/conf:/etc/smartdns/data \
        -v ${DOCKER_PATH}/work:/etc/smartdns/work \
        -d ${OWNER}/${REPO}:${TAG} \
        -c "/etc/smartdns/conf/smartdns.conf" \
        -p "/etc/smartdns/work/smartdns.pid" \
        -f
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
