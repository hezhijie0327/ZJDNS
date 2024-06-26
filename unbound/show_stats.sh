#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="unbound"
TAG="latest"

REDIS_OWNER="hezhijie0327"
REDIS_REPO="redis" # redis, valkey
REDIS_TAG="latest"

DOCKER_PATH="/docker/unbound"

ENABLE_REDIS_CACHE="" # false, true
FLUSHALL_REDIS_CACHE="" # false, true
CUSTOM_REDIS_SERVER_HOST="" # 127.0.0.1
CUSTOM_REDIS_SERVER_PORT="" # 6379

docker run -it --rm --entrypoint=/unbound-control --net host \
    -v ${DOCKER_PATH}/conf:/etc/unbound/conf \
        ${OWNER}/${REPO}:${TAG} \
    -c "/etc/unbound/conf/unbound.conf" \
    -s "127.0.0.1@8953" \
    stats_noreset

if [ "${ENABLE_REDIS_CACHE:-false}" == "true" ]; then
    if [ "${FLUSHALL_REDIS_CACHE:-false}" == "true" ]; then
        docker run -it --rm --entrypoint=/${REDIS_REPO}-cli --net host \
                ${REDIS_OWNER}/${REDIS_REPO}:${REDIS_TAG} \
            -h ${CUSTOM_REDIS_SERVER_HOST:-127.0.0.1} \
            -p ${CUSTOM_REDIS_SERVER_PORT:-6379} \
            FLUSHALL
    fi

    docker run -it --rm --entrypoint=/${REDIS_REPO}-cli --net host \
            ${REDIS_OWNER}/${REDIS_REPO}:${REDIS_TAG} \
        -h ${CUSTOM_REDIS_SERVER_HOST:-127.0.0.1} \
        -p ${CUSTOM_REDIS_SERVER_PORT:-6379} \
        info
fi
