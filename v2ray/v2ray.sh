#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="v2ray" # v2ray, xray
TAG="latest"
DOCKER_PATH="/docker/v2ray"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

LOG_LEVEL="" # debug, info, warning, error, none"

RUNNING_MODE="" # client, server
RUNTIME_PROTOCOL="" # trojan, vless, vmess

CNIPDB_SOURCE="" # bgp, dbip, geolite2, iana, ip2location, ipinfoio, ipipdotnet, iptoasn, vxlink, zjdb

CUSTOM_SERVERNAME="demo.zhijie.online" # demo.zhijie.online
CUSTOM_UUID="99235a6e-05d4-2afe-2990-5bc5cf1f5c52" # $(uuidgen | tr 'A-Z' 'a-z')

CUSTOM_DNS=() # ("1.0.0.1@53" "223.5.5.5@53#CN")
CUSTOM_IP=() # ("1.0.0.1" "1.1.1.1")

ENABLE_MUX="" # false, true
MUX_CONCURRENCY=""

ENABLE_WARP="" # false, true

SSL_CERT="fullchain.cer"
SSL_KEY="zhijie.online.key"

## Function
# Get Latest Image
function GetLatestImage() {
    docker pull ${OWNER}/${REPO}:${TAG} && IMAGES=$(docker images -f "dangling=true" -q)
}
# Cleanup Current Container
function CleanupCurrentContainer() {
    if [ "${REPO}" == "v2ray" ]; then
        TEMP_REPO="xray"
    else
        TEMP_REPO="v2ray"
    fi

    if [ $(docker ps -a --format "table {{.Names}}" | grep -E "^${REPO}$") ]; then
        docker stop ${REPO} && docker rm ${REPO}
    fi

    if [ $(docker ps -a --format "table {{.Names}}" | grep -E "^${TEMP_REPO}$") ]; then
        docker stop ${TEMP_REPO} && docker rm ${TEMP_REPO}
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
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/ZJDNS/main/v2ray/${RUNNING_MODE:-server}_${RUNTIME_PROTOCOL:-vmess}.json" > "${DOCKER_PATH}/conf/config.json" && sed -i "s/\"info\"/\"${LOG_LEVEL:-info}\"/g;s/demo.zhijie.online/${CUSTOM_SERVERNAME}/g;s/99235a6e-05d4-2afe-2990-5bc5cf1f5c52/${CUSTOM_UUID}/g;s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" "${DOCKER_PATH}/conf/config.json"

        if [ "${CUSTOM_DNS[*]}" != "" ]; then
            JSON_STRING="" && for IP in "${CUSTOM_DNS[@]}"; do
                IPADDR="" && IPADDR=$(echo ${IP} | cut -d "@" -f 1)
                PORT="" && PORT=$(echo ${IP} | cut -d "@" -f 2 | cut -d "#" -f 1)
                EXPECT="" && EXPECT=$(echo ${IP} | cut -d "#" -f 2)

                if [ "${EXPECT}" != "" ]; then
                    JSON_STRING+='{ "address": "'${IPADDR}'", "port": '${PORT:-53}', "expectIPs": [ "ext:/etc/v2ray/data/geoip.dat:cn" ] }, '
                else
                    JSON_STRING+='{ "address": "'${IPADDR}'", "port": '${PORT:-53}' }, '
                fi
            done && JSON_STRING="${JSON_STRING%, }"

            sed -i "s|{ \"address\": \"127.0.0.1\", \"port\": 53 }|${JSON_STRING}|g" "${DOCKER_PATH}/conf/config.json"
        fi

        if [ "${CUSTOM_IP[*]}" != "" ] && [ "${RUNNING_MODE:-server}" == "client" ]; then
            JSON_STRING="" && for IP in "${CUSTOM_IP[@]}"; do
                case "${RUNTIME_PROTOCOL:-vmess}" in
                    "trojan")
                        JSON_STRING+='{ "address": "'${IP}'", "port": 443, "password": "'${CUSTOM_UUID}'" }, '
                        ;;
                    "vless")
                        JSON_STRING+='{ "address": "'${IP}'", "port": 443, "users": [ { "encryption": "none", "id": "'${CUSTOM_UUID}'" } ] }, '
                        ;;
                    "vmess")
                        JSON_STRING+='{ "address": "'${IP}'", "port": 443, "users": [ { "id": "'${CUSTOM_UUID}'", "security": "auto" } ] }, '
                        ;;
                esac
            done && JSON_STRING="${JSON_STRING%, }"

            case "${RUNTIME_PROTOCOL:-vmess}" in
                "trojan")
                    sed -i "s/{ \"address\": \"${CUSTOM_SERVERNAME}\", \"port\": 443, \"password\": \"${CUSTOM_UUID}\" }/${JSON_STRING}/g" "${DOCKER_PATH}/conf/config.json"
                    ;;
                "vless")
                    sed -i "s/{ \"address\": \"${CUSTOM_SERVERNAME}\", \"port\": 443, \"users\": \\[ { \"encryption\": \"none\", \"id\": \"${CUSTOM_UUID}\" } \\] }/${JSON_STRING}/g" "${DOCKER_PATH}/conf/config.json"
                    ;;
                "vmess")
                    sed -i "s/{ \"address\": \"${CUSTOM_SERVERNAME}\", \"port\": 443, \"users\": \\[ { \"id\": \"${CUSTOM_UUID}\", \"security\": \"auto\" } \\] }/${JSON_STRING}/g" "${DOCKER_PATH}/conf/config.json"
                    ;;
            esac
        fi

        if [ "${ENABLE_MUX:-true}" != "true" ]; then
            sed -i 's/"enabled": true/"enabled": false/g' "${DOCKER_PATH}/conf/config.json"

            if [ "${MUX_CONCURRENCY:-8}" != "8" ]; then
                sed -i "s/\"concurrency\": 8,/\"concurrency\": ${MUX_CONCURRENCY},/g" "${DOCKER_PATH}/conf/config.json"
            fi
        fi

        if [ "${ENABLE_WARP:-false}" == "false" ]; then
            sed -i '/"address": "127.0.0.1", "port": 40000/d' "${DOCKER_PATH}/conf/config.json"
        fi
    fi

    if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE:-geolite2}/country_ipv4_6.dat" > "${DOCKER_PATH}/data/geoip.dat"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/v2ray/cert:ro \
        -v /etc/resolv.conf:/etc/resolv.conf:ro \
        -v ${DOCKER_PATH}/conf:/etc/v2ray/conf \
        -v ${DOCKER_PATH}/data:/etc/v2ray/data \
        -d ${OWNER}/${REPO}:${TAG} \
        run \
        -c /etc/v2ray/conf/config.json
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
