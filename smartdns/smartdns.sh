#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="smartdns"
TAG="latest"
DOCKER_PATH="/docker/smartdns"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

CNIPDB_SOURCE="" # bgp, dbip, geolite2, iana, ip2location, ipipdotnet, iptoasn, vxlink, zjdb

MAX_REPLY_IP_NUM="1" # 1 - 16 (MAX)

PREFER_REMOTE_UPSTREAM="false"

ENABLE_LOCAL_UPSTREAM="ipv64" # false, ipv4, ipv6, ipv64
ENABLE_REMOTE_UPSTREAM="ipv64" # false, ipv4, ipv6, ipv64

ENABLE_LOCAL_UPSTREAM_PROXY="false" # false, 127.0.0.1:7891
ENABLE_REMOTE_UPSTREAM_PROXY="false" # false, 127.0.0.1:7891

HTTPS_PORT="" # 5333
TLS_PORT="" # 5355
UNENCRYPTED_PORT="" # 5335

ENABLE_TLS="false"
ENABLE_UNENCRYPTED_DNS="true"

SSL_CERT="fullchain.cer"
SSL_KEY="zhijie.online.key"

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
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CMA_DNS/main/smartdns/smartdns.conf" | sed "s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" > "${DOCKER_PATH}/conf/smartdns.conf"

        if [ "${MAX_REPLY_IP_NUM}" != "1" ]; then
            sed -i "s/max-reply-ip-num 1/max-reply-ip-num ${MAX_REPLY_IP_NUM}/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${PREFER_REMOTE_UPSTREAM}" == "true" ]; then
            sed -i "s/-proxy remote_proxy/-blacklist-ip -proxy remote_proxy/g;s/-blacklist-ip -blacklist-ip/-blacklist-ip/g;s/-whitelist-ip //g" "${DOCKER_PATH}/conf/smartdns.conf" && SED_CNIPDB="blacklist"
        else
            SED_CNIPDB="whitelist"
        fi

        if [ "${ENABLE_LOCAL_UPSTREAM}" != "false" ]; then
            if [ "${ENABLE_LOCAL_UPSTREAM}" == "ipv4" ]; then
                sed -i "/local_ipv6/d;/5302/d" "${DOCKER_PATH}/conf/smartdns.conf"
            elif [ "${ENABLE_LOCAL_UPSTREAM}" == "ipv6" ]; then
                sed -i "/local_ipv4/d;/5301/d" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        else
            sed -i "/local_ipv/d;/5301/d;/5302/d" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${ENABLE_REMOTE_UPSTREAM}" != "false" ]; then
            if [ "${ENABLE_REMOTE_UPSTREAM}" == "ipv4" ]; then
                sed -i "/remote_ipv6/d;/5304/d" "${DOCKER_PATH}/conf/smartdns.conf"
            elif [ "${ENABLE_REMOTE_UPSTREAM}" == "ipv6" ]; then
                sed -i "/remote_ipv4/d;/5303/d" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        else
            sed -i "/remote_ipv/d;/5303/d;/5304/d" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${ENABLE_LOCAL_UPSTREAM_PROXY}" == "false" ]; then
            sed -i "s/ -proxy local_proxy//g" "${DOCKER_PATH}/conf/smartdns.conf"
        else
            sed -i "s|socks5://127.0.0.1:7891 -name local_proxy|socks5://${ENABLE_LOCAL_UPSTREAM_PROXY} -name local_proxy|g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${ENABLE_REMOTE_UPSTREAM_PROXY}" == "false" ]; then
            sed -i "s/ -proxy remote_proxy//g" "${DOCKER_PATH}/conf/smartdns.conf"
        else
            sed -i "s|socks5://127.0.0.1:7891 -name remote_proxy|socks5://${ENABLE_REMOTE_UPSTREAM_PROXY} -name remote_proxy|g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${ENABLE_UNENCRYPTED_DNS}" == "false" ]; then
            if [ "${ENABLE_TLS}" == "true" ]; then
                sed -i "/bind [::]:5335/d;/bind-tcp [::]:5335/d" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        else
            if [ "${UNENCRYPTED_PORT:-5335}" != "5335" ]; then
                sed "s/bind [::]:5335/bind [::]:${UNENCRYPTED_PORT}/g;s/bind-tcp [::]:5335/bind-tcp [::]:${UNENCRYPTED_PORT}/g" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        fi
        if [ "${ENABLE_TLS}" == "false" ]; then
            sed -i "/bind-cert/d;/bind-tls/d" "${DOCKER_PATH}/conf/smartdns.conf"
        else
            if [ "${TLS_PORT:-5355}" != "5355" ]; then
                sed "s/bind-tls [::]:5355/bind-tls [::]:${TLS_PORT}/g" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        fi

        if [ -f "${DOCKER_PATH}/conf/smartdns.conf" ]; then
            sed -i "/#/d" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ ! -d "${DOCKER_PATH}/data" ]; then
            mkdir -p "${DOCKER_PATH}/data"
        fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE:-geolite2}/country_ipv4_6.txt" | sed "s/^/${SED_CNIPDB}-ip /g" > "${DOCKER_PATH}/data/GeoIP_CNIPDb.conf"
    fi
}
# Create New Container
function CreateNewContainer() {
    if [ ! -d "${DOCKER_PATH}/conf" ]; then
        mkdir -p "${DOCKER_PATH}/conf"
    fi

    if [ ! -d "${DOCKER_PATH}/work" ]; then
        mkdir -p "${DOCKER_PATH}/work"
    fi

    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/smartdns/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/smartdns/conf \
        -v ${DOCKER_PATH}/conf:/etc/smartdns/data \
        -v ${DOCKER_PATH}/work:/etc/smartdns/work \
        -d ${OWNER}/${REPO}:${TAG} \
        -c "/etc/smartdns/conf/smartdns.conf" \
        -p "/etc/smartdns/work/smartdns.pid" \
        -f
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
