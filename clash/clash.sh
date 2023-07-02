#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="clash"
TAG="latest" # latest, meta
DOCKER_PATH="/docker/clash"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

CNIPDB_SOURCE="" # bgp, dbip, geolite2, iana, ip2location, ipipdotnet, iptoasn, vxlink, zjdb

CUSTOM_SERVER="" # demo.zhijie.online
CUSTOM_SERVERNAME="" # demo.zhijie.online
CUSTOM_UUID="" # 99235a6e-05d4-2afe-2990-5bc5cf1f5c52

ENABLE_SHADOWSOCKS_WSS="false"
ENABLE_TROJAN_GRPC="false"
ENABLE_TROJAN_WSS="false"
ENABLE_VLESS_GRPC="false"
ENABLE_VLESS_WSS="false"
ENABLE_VMESS_GRPC="false"
ENABLE_VMESS_WSS="true"

RUNNING_MODE="" # fallback, load-balance, url-test

## Function
# Get Latest Image
function GetLatestImage() {
    if [ "${ENABLE_VLESS_GRPC}" == "true" ] || [ "${ENABLE_VLESS_WSS}" == "true" ]; then
        TAG="meta"
    fi && docker pull ${OWNER}/${REPO}:${TAG} && IMAGES=$(docker images -f "dangling=true" -q)
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
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CMA_DNS/main/clash/config.yaml" > "${DOCKER_PATH}/conf/config.yaml" && sed -i "s/server: demo.zhijie.online/server: ${CUSTOM_SERVER:-demo.zhijie.online}/g;s/Host: demo.zhijie.online/Host: ${CUSTOM_SERVERNAME:-${CUSTOM_SERVER:-demo.zhijie.online}}/g;s/host: demo.zhijie.online/host: ${CUSTOM_SERVERNAME:-${CUSTOM_SERVER:-demo.zhijie.online}}/g;s/servername: demo.zhijie.online/servername: ${CUSTOM_SERVERNAME:-${CUSTOM_SERVER:-demo.zhijie.online}}/g;s/sni: demo.zhijie.online/sni: ${CUSTOM_SERVERNAME:-${CUSTOM_SERVER:-demo.zhijie.online}}/g;s/99235a6e-05d4-2afe-2990-5bc5cf1f5c52/${CUSTOM_UUID:-$(uuidgen | tr 'A-Z' 'a-z')}/g" "${DOCKER_PATH}/conf/config.yaml"

        if [ "${ENABLE_SHADOWSOCKS_WSS}" == "true" ]; then
            sed -i 's/#+/  /g' "${DOCKER_PATH}/conf/config.yaml"
            PROXY_LIST="SHADOWSOCKS_WSS ${PROXY_LIST}"
        fi
        if [ "${ENABLE_TROJAN_GRPC}" == "true" ]; then
            sed -i 's/#(/  /g' "${DOCKER_PATH}/conf/config.yaml"
            PROXY_LIST="TROJAN_GRPC ${PROXY_LIST}"
        fi
        if [ "${ENABLE_TROJAN_WSS}" == "true" ]; then
            sed -i 's/#)/  /g' "${DOCKER_PATH}/conf/config.yaml"
            PROXY_LIST="TROJAN_WSS ${PROXY_LIST}"
        fi
        if [ "${ENABLE_VLESS_GRPC}" == "true" ]; then
            sed -i 's/#</  /g' "${DOCKER_PATH}/conf/config.yaml"
            PROXY_LIST="VLESS_GRPC ${PROXY_LIST}"
        fi
        if [ "${ENABLE_VLESS_WSS}" == "true" ]; then
            sed -i 's/#>/  /g' "${DOCKER_PATH}/conf/config.yaml"
            PROXY_LIST="VLESS_WSS ${PROXY_LIST}"
        fi
        if [ "${ENABLE_VMESS_GRPC}" == "true" ]; then
            sed -i 's/##/  /g' "${DOCKER_PATH}/conf/config.yaml"
            PROXY_LIST="VMESS_GRPC ${PROXY_LIST}"
        fi
        if [ "${ENABLE_VMESS_WSS}" == "false" ]; then
            if [ "${ENABLE_SHADOWSOCKS_WSS}" != "false" ] || [ "${ENABLE_TROJAN_GRPC}" != "false" ] || [ "${ENABLE_TROJAN_WSS}" != "false" ] || [ "${ENABLE_VLESS_GRPC}" != "false" ] || [ "${ENABLE_VLESS_WSS}" != "false" ] || [ "${ENABLE_VMESS_GRPC}" != "false" ]; then
                sed -i 's/  - { name: VMESS_WSS/##- { name: VMESS_WSS/g' "${DOCKER_PATH}/conf/config.yaml"
            else
                PROXY_LIST="VMESS_WSS ${PROXY_LIST}"
            fi
        else
            PROXY_LIST="VMESS_WSS ${PROXY_LIST}"
        fi

        sed -i "s/\[VMESS_WSS\]/\[$(echo ${PROXY_LIST} | sed 's/ $//g;s/ /, /g')\]/g" "${DOCKER_PATH}/conf/config.yaml"

        if [ "${RUNNING_MODE}" == "fallback" ] || [ "${RUNNING_MODE}" == "load-balance" ] || [ "${RUNNING_MODE}" == "url-test" ]; then
            sed -i "s/fallback/${RUNNING_MODE}/g" "${DOCKER_PATH}/conf/config.yaml"
        fi

        if [ -f "${DOCKER_PATH}/conf/config.yaml" ]; then
            sed -i "/#/d" "${DOCKER_PATH}/conf/config.yaml"
        fi
    fi

    if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE:-geolite2}/country_ipv4_6.mmdb" > "${DOCKER_PATH}/data/Country.mmdb"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /etc/resolv.conf:/etc/resolv.conf:ro \
        -v ${DOCKER_PATH}/conf:/etc/clash/conf \
        -v ${DOCKER_PATH}/data:/etc/clash/data \
        -d ${OWNER}/${REPO}:${TAG} \
        -d "/etc/clash/data" \
        -f "/etc/clash/conf/config.yaml"
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
