#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="unbound"
TAG="latest"
DOCKER_PATH="/docker/unbound"

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
# Update Root Hints
function UpdateRootHints() {
    curl -s --connect-timeout 15 "https://www.internic.net/domain/named.cache" > "${DOCKER_PATH}/root.hints"
}
# Create New Container
function CreateNewContainer() {
    docker run --name redis --net host --restart=always \
        -v ${DOCKER_PATH}/redis:/data \
        -d redis:latest \
        --aof-use-rdb-preamble yes \
        --appendfsync everysec \
        --appendonly yes \
        --lazyfree-lazy-eviction yes \
        --lazyfree-lazy-expire yes \
        --lazyfree-lazy-server-del yes \
        --maxmemory 64MB \
        --maxmemory-policy allkeys-lru \
        --maxmemory-samples 10
    docker run -it --rm --entrypoint=/unbound-anchor \
        -v ${DOCKER_PATH}:/usr/local/etc/unbound \
           ${OWNER}/${REPO}:${TAG}
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/usr/local/etc/ssl:ro \
        -v ${DOCKER_PATH}:/usr/local/etc/unbound \
        -d ${OWNER}/${REPO}:${TAG} \
        -c "/usr/local/etc/unbound/unbound.conf" \
        -d
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
# Call UpdateRootHints
UpdateRootHints
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
