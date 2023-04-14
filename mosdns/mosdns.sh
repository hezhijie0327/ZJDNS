#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="mosdns"
TAG="latest"
DOCKER_PATH="/docker/mosdns"

CURL_OPTION=""
USE_CDN="true"

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
# Download mosDNS Configuration
function DownloadmosDNSConfiguration() {
    ENABLE_ALWAYS_STANDBY="false"
    ENABLE_IPV6_UPSTREAM="false"
    ENABLE_HTTP3_UPSTREAM="false"
    ENABLE_PIPELINE="false"

    ENABLE_PROXY_IPV6_UPSTREAM="false"
    ENABLE_PROXY_UPSTREAM="false"

    ENABLE_RECURSIVE_UPSTREAM="false"

    ENABLE_REMOTE_IPV6_UPSTREAM="false"
    ENABLE_REMOTE_UPSTREAM="false"

    ENABLE_ECS="true"
    ECS_IPV4_OVERWRITE="255.255.255.255"
    ECS_IPV6_OVERWRITE="ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"

    ENABLE_HTTPS="false"
    ENABLE_TLS="false"
    ENABLE_UNENCRYPTED_DNS="true"
    SSL_CERT="fullchain.cer"
    SSL_KEY="zhijie.online.key"
    HTTPS_CONFIG=(
        "  - tag: create_https_server"
        "    type: tcp_server"
        "    args:"
        "      entries:"
        "        - path: '/dns-query'"
        "          exec: main_server"
        "      cert: '/etc/mosdns/cert/${SSL_CERT}'"
        "      key: '/etc/mosdns/cert/${SSL_KEY}'"
        "      listen: :5553"
    )
    TLS_CONFIG=(
        "  - tag: create_tls_server"
        "    type: tcp_server"
        "    args:"
        "      entry: main_server"
        "      cert: '/etc/mosdns/cert/${SSL_CERT}'"
        "      key: '/etc/mosdns/cert/${SSL_KEY}'"
        "      listen: :5535"
    )

    if [ "${USE_CDN}" == "true" ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CMA_DNS/main/mosdns/config.yaml" > "${DOCKER_PATH}/conf/config.yaml"

    if [ "${ENABLE_ALWAYS_STANDBY}" == "true" ]; then
        sed -i 's/#!/  /g' "${DOCKER_PATH}/conf/config.yaml"
    fi
    if [ "${ENABLE_IPV6_UPSTREAM}" == "true" ]; then
        sed -i "s/#-/  /g" "${DOCKER_PATH}/conf/config.yaml"
    fi
    if [ "${ENABLE_HTTP3_UPSTREAM}" == "true" ]; then
        sed -i "s/##/  /g" "${DOCKER_PATH}/conf/config.yaml"
    fi
    if [ "${ENABLE_PIPELINE}" == "false" ]; then
        sed -i "s/enable_pipeline: true/enable_pipeline: false/g" "${DOCKER_PATH}/conf/config.yaml"
    fi

    if [ "${ENABLE_PROXY_IPV6_UPSTREAM}" == "true" ]; then
        sed -i "s/#+/  /g" "${DOCKER_PATH}/conf/config.yaml"
    fi
    if [ "${ENABLE_PROXY_UPSTREAM}" == "true" ]; then
        sed -i "s/#@/  /g" "${DOCKER_PATH}/conf/config.yaml"
    fi

    if [ "${ENABLE_RECURSIVE_UPSTREAM}" == "true" ]; then
        sed -i "s/#~/  /g" "${DOCKER_PATH}/conf/config.yaml"
    fi

    if [ "${ENABLE_REMOTE_IPV6_UPSTREAM}" == "true" ]; then
        sed -i "s/#=/  /g" "${DOCKER_PATH}/conf/config.yaml"
    fi
    if [ "${ENABLE_REMOTE_UPSTREAM}" == "true" ]; then
        sed -i "s/#?/  /g" "${DOCKER_PATH}/conf/config.yaml"
    fi

    if [ "${ENABLE_ECS}" == "true" ]; then
        sed -i "s/#%/  /g" "${DOCKER_PATH}/conf/config.yaml"
    fi
    if [ "${ECS_IPV4_OVERWRITE}" != "255.255.255.255" ]; then
        sed -i "s/- exec: ecs/- exec: ecs ${ECS_IPV4_OVERWRITE}\/24/g" "${DOCKER_PATH}/conf/config.yaml"
    fi
    if [ "${ECS_IPV6_OVERWRITE}" != "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff" ]; then
        sed -i "s/- exec: ecs/- exec: ecs ${ECS_IPV6_OVERWRITE//:/\:}\/56/g" "${DOCKER_PATH}/conf/config.yaml"
    fi

    if [ "${ENABLE_UNENCRYPTED_DNS}" == "false" ]; then
        if [ "${ENABLE_HTTPS}" == "true" ] || [ "${ENABLE_TLS}" == "true" ]; then
            for i in $(seq 1 10); do
                sed -i '$d' "${DOCKER_PATH}/conf/config.yaml"
            done
        fi
    fi
    if [ "${ENABLE_HTTPS}" == "true" ]; then
        for HTTPS_CONFIG_TASK in "${!HTTPS_CONFIG[@]}"; do
            echo "${HTTPS_CONFIG[$HTTPS_CONFIG_TASK]}" >> "${DOCKER_PATH}/conf/config.yaml"
        done
    fi
    if [ "${ENABLE_TLS}" == "true" ]; then
        for TLS_CONFIG_TASK in "${!TLS_CONFIG[@]}"; do
            echo "${TLS_CONFIG[$TLS_CONFIG_TASK]}" >> "${DOCKER_PATH}/conf/config.yaml"
        done
    fi
}
# Update GeoIP CN Rule
function UpdateGeoIPCNRule() {
    CNIPDB_SOURCE="geolite2"
    curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE}/country_ipv4_6.txt" > "${DOCKER_PATH}/data/GeoIP_CNIPDb.txt"
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/mosdns/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/mosdns/conf \
        -v ${DOCKER_PATH}/data:/etc/mosdns/data \
        -d ${OWNER}/${REPO}:${TAG} \
        start \
        -c "/etc/mosdns/conf/config.yaml" \
        -d "/etc/mosdns/data"
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
# Call DownloadmosDNSConfiguration
DownloadmosDNSConfiguration
# Call UpdateGeoIPRule
UpdateGeoIPCNRule
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
