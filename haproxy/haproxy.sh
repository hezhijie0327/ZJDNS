#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="haproxy"
TAG="latest"
DOCKER_PATH="/docker/haproxy"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

RUNNING_MODE="" # server, server-template
CUSTOM_DNS_RESULT_NUM="" # 1, 5, 10, 15

HAPROXY_STATS_AUTH_USER="" # admin:admin, admin:'*admin*'

IP_GROUP=() # ("127.0.0.1" "127.0.0.1@443" "127.0.0.1#backup" "127.0.0.1@443#backup")

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
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/ZJDNS/main/haproxy/haproxy.cfg" > "${DOCKER_PATH}/conf/haproxy.cfg" && sed -i "s/zhijie\.online\.cert/${SSL_CERT/./\\.}/g" "${DOCKER_PATH}/conf/haproxy.cfg"

        if [ "${HAPROXY_STATS_AUTH_USER}" != "" ]; then
            sed -i "s|admin:admin|${HAPROXY_STATS_AUTH_USER}|g" "${DOCKER_PATH}/conf/haproxy.cfg"
        fi

        if [ "${IP_GROUP[*]}" != "" ]; then
            for IP in ${IP_GROUP[*]}; do
                OPTION=$(echo ${IP} | grep '#' | cut -d '#' -f 2)
                PORT=$(echo ${IP} | grep '@' | cut -d '@' -f 2 | cut -d '#' -f 1)
                IP=$(echo ${IP} | cut -d '@' -f 1 | cut -d '#' -f 1)

                if [ ! -z "${OPTION}" ]; then
                    OPTION=" ${OPTION}"
                fi

                if [ "${RUNNING_MODE:-server}" == "server" ]; then
                    echo "    server $(echo ${IP} | tr '.:' '_' | tr -d '[]') ${IP}:${PORT:-443} check-ssl inter 1000${OPTION}" >> "${DOCKER_PATH}/conf/haproxy.cfg"
                else
                    echo "    server-template $(echo ${IP} | tr '.:' '_' | tr -d '[]')_ ${CUSTOM_DNS_RESULT_NUM:-1} ${IP}:${PORT:-443} check-ssl resolvers v2ray_dns inter 1000${OPTION}" >> "${DOCKER_PATH}/conf/haproxy.cfg"
                fi
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
