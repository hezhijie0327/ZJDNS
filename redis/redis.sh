#!/bin/bash

# Parameter
OWNER="library"
REPO="redis"
TAG="latest"
DOCKER_PATH="/docker/redis"

REDIS_MAXMEMORY=""
REDIS_MAXMEMORY_POLICY=""

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
    if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi

    docker run --name redis --net host --restart=always \
        -v ${DOCKER_PATH}/data:/data \
        -d ${OWNER}/${REPO}:${TAG} \
        --activedefrag yes \
        --aof-use-rdb-preamble yes \
        --appendfsync always \
        --appendonly yes \
        --lazyfree-lazy-eviction yes \
        --lazyfree-lazy-expire yes \
        --lazyfree-lazy-server-del yes \
        --lfu-decay-time 1 \
        --lfu-log-factor 10 \
        --maxmemory ${REDIS_MAXMEMORY:-4MB} \
        --maxmemory-policy ${REDIS_MAXMEMORY_POLICY:-volatile-ttl} \
        --maxmemory-samples 10
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
