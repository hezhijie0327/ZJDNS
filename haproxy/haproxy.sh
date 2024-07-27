#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="haproxy"
TAG="latest"
DOCKER_PATH="/docker/haproxy"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

LOG_LEVEL="" # emerg, alert, crit, err, warning, notice, info, debug

HAPROXY_STATS_AUTH_USER="" # admin:admin, admin:'*admin*'

CUSTOM_IP=() # ("1.0.0.1" "1.1.1.1" "127.0.0.1@443")

SSL_CERT="zhijie.online.cert"

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
# Download Configuration
function DownloadConfiguration() {
    if [ "${USE_CDN}" == "true" ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi

    if [ ! -d "${DOCKER_PATH}/conf" ]; then
        mkdir -p "${DOCKER_PATH}/conf"
    fi

    if [ "${DOWNLOAD_CONFIG:-true}" == "true" ]; then
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/ZJDNS/main/haproxy/haproxy.cfg" > "${DOCKER_PATH}/conf/haproxy.cfg" && sed -i "s/local0 info/local0 ${LOG_LEVEL:-info}/g;s/zhijie\.online\.cert/${SSL_CERT/./\\.}/g" "${DOCKER_PATH}/conf/haproxy.cfg"

        if [ "${HAPROXY_STATS_AUTH_USER}" != "" ]; then
            sed -i "s|admin:admin|${HAPROXY_STATS_AUTH_USER}|g" "${DOCKER_PATH}/conf/haproxy.cfg"
        else
            sed -i "|stats auth|d" "${DOCKER_PATH}/conf/haproxy.cfg"
        fi

        if [ "${CUSTOM_IP[*]}" != "" ]; then
            if [ -z "$(echo "${IP}" | grep "@")" ]; then
                PORT="443"
            else
                PORT=$(echo ${IP} | cut -d "@" -f 2)
                IP=$(echo ${IP} | cut -d "@" -f 1)
            fi

            for IP in ${CUSTOM_IP[*]}; do
                echo "    server ${IP} ${IP}:${PORT} check" >> "${DOCKER_PATH}/conf/haproxy.cfg"
            done
        fi
    fi
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/haproxy/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/haproxy/conf \
        -d ${OWNER}/${REPO}:${TAG} \
        -f /etc/haproxy/conf/haproxy.cfg
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
# Call DownloadConfiguration
DownloadConfiguration
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
