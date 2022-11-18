#!/bin/bash

# Parameter
OWNER="library"
REPO="redis"
TAG="latest"
DOCKER_PATH="/docker/redis"
REDIS_MAXMEMORY="64MB"

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
    docker run --name redis --net host --restart=always \
        -v ${DOCKER_PATH}/data:/data \
        -d ${OWNER}/${REPO}:${TAG} \
        --aof-use-rdb-preamble yes \
        --appendfsync everysec \
        --appendonly yes \
        --lazyfree-lazy-eviction yes \
        --lazyfree-lazy-expire yes \
        --lazyfree-lazy-server-del yes \
        --maxmemory ${REDIS_MAXMEMORY} \
        --maxmemory-policy allkeys-lru \
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
