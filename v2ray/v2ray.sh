#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="v2ray" # v2ray, xray
TAG="latest"
DOCKER_PATH="/docker/v2ray"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

LOG_LEVEL="" # debug, info, warning, error, none

RUNNING_MODE="" # client, server
RUNTIME_PROTOCOL="" # trojan, vless, vmess
RUNTIME_TRANSPORT="" # grpc, httpupgrade, ws, xhttp

CNIPDB_SOURCE="" # bgp, dbip, geolite2, iana, ip2location, ipinfoio, ipipdotnet, iptoasn, vxlink, zjdb

CUSTOM_SERVERNAME="demo.zhijie.online" # demo.zhijie.online
CUSTOM_UUID="99235a6e-05d4-2afe-2990-5bc5cf1f5c52" # $(uuidgen | tr 'A-Z' 'a-z')

ENABLE_ENCRYPT_PATH="" #false, true
CUSTOM_ENCRYPT_PATH="$(date +%Y-%m-%W)" # YEAR-MONTH-WEEK

ENABLE_DNS="" # false, true
ENABLE_DNS_CACHE="" # false, true
CUSTOM_DNS=() # ("1.0.0.1@53" "223.5.5.5@53#CN" "8.8.8.8@53%1.1.1.1" "8.8.4.4@53%auto&AAAA")
CUSTOM_IP=() # ("1.0.0.1" "1.1.1.1" "127.0.0.1@7891")

ENABLE_MUX="" # false, true
MUX_CONCURRENCY=""

ENABLE_WARP="" # false, true

SSL_CERT="fullchain.cer"
SSL_KEY="zhijie.online.key"

## Function
# Get WAN IP
function GetWANIP() {
    if [ "${Type}" == "A" ]; then
        IPv4_v6="4"
        IP_REGEX="^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}$"
    else
        IPv4_v6="6"
        IP_REGEX="^(([0-9a-f]{1,4}:){7,7}[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,7}:|([0-9a-f]{1,4}:){1,6}:[0-9a-f]{1,4}|([0-9a-f]{1,4}:){1,5}(:[0-9a-f]{1,4}){1,2}|([0-9a-f]{1,4}:){1,4}(:[0-9a-f]{1,4}){1,3}|([0-9a-f]{1,4}:){1,3}(:[0-9a-f]{1,4}){1,4}|([0-9a-f]{1,4}:){1,2}(:[0-9a-f]{1,4}){1,5}|[0-9a-f]{1,4}:((:[0-9a-f]{1,4}){1,6})|:((:[0-9a-f]{1,4}){1,7}|:)|fe80:(:[0-9a-f]{0,4}){0,4}%[0-9a-z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-f]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))$"
    fi
    if [ "${StaticIP:-auto}" == "auto" ]; then
        IP_RESULT=$(curl -${IPv4_v6:-4} -s --connect-timeout 15 "https://api.cloudflare.com/cdn-cgi/trace" | grep "ip=" | sed "s/ip=//g" | grep -E "${IP_REGEX}")
        if [ "${IP_RESULT}" == "" ]; then
            IP_RESULT=$(curl -${IPv4_v6:-4} -s --connect-timeout 15 "https://api64.ipify.org" | grep -E "${IP_REGEX}")
            if [ "${IP_RESULT}" == "" ]; then
                IP_RESULT=$(dig -${IPv4_v6:-4} +short TXT @ns1.google.com o-o.myaddr.l.google.com | tr -d '"' | grep -E "${IP_REGEX}")
                if [ "${IP_RESULT}" == "" ]; then
                    IP_RESULT=$(dig -${IPv4_v6:-4} +short ANY @resolver1.opendns.com myip.opendns.com | grep -E "${IP_REGEX}")
                    if [ "${IP_RESULT}" == "" ]; then
                        echo "invalid"
                    else
                        echo "${IP_RESULT}"
                    fi
                else
                    echo "${IP_RESULT}"
                fi
            else
                echo "${IP_RESULT}"
            fi
        else
            echo "${IP_RESULT}"
        fi
    else
        if [ "$(echo ${StaticIP} | grep ',')" != "" ]; then
            if [ "${Type}" == "A" ]; then
                IP_RESULT=$(echo "${StaticIP}" | cut -d ',' -f 1 | grep -E "${IP_REGEX}")
            else
                IP_RESULT=$(echo "${StaticIP}" | cut -d ',' -f 2 | grep -E "${IP_REGEX}")
            fi
            if [ "${IP_RESULT}" == "" ]; then
                echo "invalid"
            else
                echo "${IP_RESULT}"
            fi
        else
            IP_RESULT=$(echo "${StaticIP}" | grep -E "${IP_REGEX}")
            if [ "${IP_RESULT}" == "" ]; then
                echo "invalid"
            else
                echo "${IP_RESULT}"
            fi
        fi
    fi
}
# Get Latest Image
function GetLatestImage() {
    if [ "${RUNTIME_TRANSPORT}" == "httpupgrade" ] || [ "${RUNTIME_TRANSPORT}" == "xhttp" ]; then
        REPO="xray"
    fi

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
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/ZJDNS/main/v2ray/${RUNNING_MODE:-server}_${RUNTIME_PROTOCOL:-vmess}.json" > "${DOCKER_PATH}/conf/config.json" && sed -i "s/\"grpc\"/\"${RUNTIME_TRANSPORT:-grpc}\"/g;s/\"info\"/\"${LOG_LEVEL:-info}\"/g;s/demo.zhijie.online/${CUSTOM_SERVERNAME}/g;s/99235a6e-05d4-2afe-2990-5bc5cf1f5c52/${CUSTOM_UUID}/g;s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" "${DOCKER_PATH}/conf/config.json"

        if [ "${ENABLE_ENCRYPT_PATH:-false}" != "false" ]; then
            sed -i "s|gRPC4VLESS|$(echo -n ${CUSTOM_ENCRYPT_PATH}gRPC4VLESS${CUSTOM_UUID} | base64 | sha256sum | awk '{print $1}')|g;s|HTTPUpgrade4VLESS|$(echo -n ${CUSTOM_ENCRYPT_PATH}HTTPUpgrade4VLESS${CUSTOM_UUID} | base64 | sha256sum | awk '{print $1}')|g;s|WebSocket4VLESS|$(echo -n ${CUSTOM_ENCRYPT_PATH}WebSocket4VLESS${CUSTOM_UUID} | base64 | sha256sum | awk '{print $1}')|g;s|XHTTP4VLESS|$(echo -n ${CUSTOM_ENCRYPT_PATH}XHTTP4VLESS${CUSTOM_UUID} | base64 | sha256sum | awk '{print $1}')|g" "${DOCKER_PATH}/conf/config.json"
        fi

        if [ "${ENABLE_DNS_CACHE:-false}" != "false" ]; then
            sed -i 's/"disableCache": true/"disableCache": false/g' "${DOCKER_PATH}/conf/config.json"
        fi

        if [ "${CUSTOM_DNS[*]}" != "" ]; then
            JSON_STRING="" && for IP in "${CUSTOM_DNS[@]}"; do
                IPADDR="" && IPADDR=$(echo ${IP} | cut -d "@" -f 1)
                PORT="" && PORT=$(echo ${IP} | grep '@' | cut -d "@" -f 2 | cut -d "#" -f 1 | cut -d "%" -f 1 | cut -d "&" -f 1)
                EXPECT="" && EXPECT=$(echo ${IP} | grep '#' | cut -d "#" -f 2 | cut -d "%" -f 1 | cut -d "&" -f 1)
                CLIENT="" && CLIENT=$(echo ${IP} | grep '%' | cut -d "%" -f 2 | cut -d "&" -f 1)
                TYPE="" && TYPE=$(echo ${IP} | grep '&' | cut -d "&" -f 2)

                ADDITIONAL="" && if [ "${CLIENT}" != "" ]; then
                    ADDITIONAL=', "clientIp": "'$(StaticIP=${CLIENT} && Type=${TYPE:-A} && GetWANIP)'"'
                fi

                if [ "${EXPECT}" != "" ]; then
                    if [ "${EXPECT}" == "CN" ]; then
                        JSON_STRING+='{ "address": "'${IPADDR}'", "port": '${PORT:-53}''${ADDITIONAL}', "expectIPs": [ "ext:/etc/v2ray/data/geoip.dat:cn" ] }, '
                    else
                        JSON_STRING+='{ "address": "'${IPADDR}'", "port": '${PORT:-53}''${ADDITIONAL}', "expectIPs": [ "ext:/etc/v2ray/data/geoip.dat:!cn" ] }, '
                    fi
                else
                    JSON_STRING+='{ "address": "'${IPADDR}'", "port": '${PORT:-53}''${ADDITIONAL}' }, '
                fi
            done && JSON_STRING="${JSON_STRING%, }"

            sed -i "s|{ \"address\": \"127.0.0.1\", \"port\": 53 }|${JSON_STRING}|g" "${DOCKER_PATH}/conf/config.json"
        fi

        if [ "${CUSTOM_IP[*]}" != "" ] && [ "${RUNNING_MODE:-server}" == "client" ]; then
            JSON_STRING="" && for IP in "${CUSTOM_IP[@]}"; do
                if [ -z "$(echo "${IP}" | grep "@")" ]; then
                    PORT="443"
                else
                    PORT=$(echo ${IP} | cut -d "@" -f 2)
                    IP=$(echo ${IP} | cut -d "@" -f 1)
                fi

                case "${RUNTIME_PROTOCOL:-vmess}" in
                    "trojan")
                        JSON_STRING+='{ "address": "'${IP}'", "port": '${PORT}', "password": "'${CUSTOM_UUID}'" }, '
                        ;;
                    "vless")
                        JSON_STRING+='{ "address": "'${IP}'", "port": '${PORT}', "users": [ { "encryption": "none", "id": "'${CUSTOM_UUID}'" } ] }, '
                        ;;
                    "vmess")
                        JSON_STRING+='{ "address": "'${IP}'", "port": '${PORT}', "users": [ { "id": "'${CUSTOM_UUID}'", "security": "auto" } ] }, '
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

    if [ "${ENABLE_DNS:-true}" != "true" ]; then
        cat "${DOCKER_PATH}/conf/config.json" | jq 'del(.dns)' > "${DOCKER_PATH}/conf/config.json.tmp" && mv "${DOCKER_PATH}/conf/config.json.tmp" "${DOCKER_PATH}/conf/config.json"
    fi

    if [ "${REPO}" != "xray" ]; then
        cat "${DOCKER_PATH}/conf/config.json" | jq 'del(..|.httpupgradeSettings?) | del(..|.xhttpSettings?)' > "${DOCKER_PATH}/conf/config.json.tmp" && mv "${DOCKER_PATH}/conf/config.json.tmp" "${DOCKER_PATH}/conf/config.json"
    fi

    if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE:-geolite2}/country_ipv4_6.dat" > "${DOCKER_PATH}/data/geoip.dat"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        --privileged \
        -v /docker/ssl:/etc/v2ray/cert:ro \
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
