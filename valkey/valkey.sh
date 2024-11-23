#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="valkey"
TAG="latest"
DOCKER_PATH="/docker/redis"

VALKEY_DATABASES="" # 16
VALKEY_MAXMEMORY="" # 4MB
VALKEY_MAXMEMORY_POLICY="" # noeviction, allkeys-lru, volatile-lru, allkeys-random, volatile-random, volatile-ttl, volatile-lfu, allkeys-lfu
VALKEY_PASSWORD=''
VALKEY_PORT="" # 6379

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
        -v ${DOCKER_PATH}/data:/etc/redis/data \
        -d ${OWNER}/${REPO}:${TAG} \
        --activedefrag yes \
        --aof-use-rdb-preamble yes \
        --appendfsync everysec \
        --appendonly yes \
        --databases ${VALKEY_DATABASES:-16} \
        --dir /etc/redis/data \
        --lazyfree-lazy-eviction yes \
        --lazyfree-lazy-expire yes \
        --lazyfree-lazy-server-del yes \
        --lazyfree-lazy-user-del yes \
        --lazyfree-lazy-user-flush yes \
        --lfu-decay-time 1 \
        --lfu-log-factor 10 \
        --maxmemory ${VALKEY_MAXMEMORY:-4MB} \
        --maxmemory-policy ${VALKEY_MAXMEMORY_POLICY:-volatile-ttl} \
        --maxmemory-samples 10 \
        --port ${VALKEY_PORT:-6379} \
        --protected-mode no \
        --replica-lazy-flush yes \
        --requirepass ${VALKEY_PASSWORD}
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
