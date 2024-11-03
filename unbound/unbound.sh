#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="unbound"
TAG="latest"

DOCKER_PATH="/docker/unbound"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

NUM_THREADS="auto" # auto, 1
ENABLE_FORK_OPERATION="" # false, true

ENABLE_DNSSEC="false"
ENABLE_DNSSEC_PERMISSIVE_MODE="false"

ENABLE_ECS="true"

ENABLE_FORWARD="true"
ENABLE_FORWARD_CACHE="true"
ENABLE_RECURSIVE_DNS="false"

ENABLE_IPV4="true"
ENABLE_IPV6="true"
ENABLE_IP64="false"

ENABLE_LOGFILE="false"

ENABLE_RATELIMIT="false"

ENABLE_USE_CAPS_FOR_ID="false"

ENABLE_PREFETCH="false"
ENABLE_PREFETCH_KEY="true"

ENABLE_SERVE_EXPIRED="false"
ENABLE_SERVE_EXPIRED_TTL_RESET="true"
ENABLE_SERVE_ORIGINAL_TTL="false"
SERVE_EXPIRED_CLIENT_TIMEOUT="" # 0, 1800
SERVE_EXPIRED_TTL="" # 0, 86400, 259200

CACHE_SIZE_KEY="" # 4m
CACHE_SIZE_MSG="" # 4m
CACHE_SIZE_NEG="" # 1m
CACHE_SIZE_RRSET="" # 4m

ENABLE_REDIS_CACHE="false"
ENABLE_REDIS_CACHE_CHECK_WHEN_SERVE_EXPIRED="false"
CUSTOM_REDIS_LOGICAL_DB="" # 0
CUSTOM_REDIS_SERVER_HOST="" # 127.0.0.1
CUSTOM_REDIS_SERVER_PASSWORD=""
CUSTOM_REDIS_SERVER_PATH=""
CUSTOM_REDIS_SERVER_PORT="" # 6379
CUSTOM_SECRET_SEED=$(hostname) # default, $(hostname)

ENABLE_REMOTE_CONTROL="true"

CUSTOM_UPSTREAM=() # ("127.0.0.1@5533")
ENABLE_TCP_UPSTREAM="false"
ENABLE_TLS_UPSTREAM="false"

HTTPS_PORT="" # 3353
TLS_PORT="" # 3533
UNENCRYPTED_PORT="" # 3553

ENABLE_HTTPS="false"
ENABLE_TLS="false"
ENABLE_UNENCRYPTED_DNS="true"

SSL_CERT="fullchain.cer"
SSL_KEY="zhijie.online.key"

## Function
# Caculate Cache Size
function CaculateCacheSize() {
    value=$(echo "$1" | sed 's/[^0-9.]//g')
    unit=$(echo "$1" | sed 's/[0-9.]*//g')

    case $unit in
        k|K) calculated_bytes=$(echo "$value * 1024^1" | bc) ;;
        m|M) calculated_bytes=$(echo "$value * 1024^2" | bc) ;;
        g|G) calculated_bytes=$(echo "$value * 1024^3" | bc) ;;
        t|T) calculated_bytes=$(echo "$value * 1024^4" | bc) ;;
        *) calculated_bytes="$value" ;;
    esac

    if [ "$2" != "" ]; then
        echo $(echo $calculated_bytes | awk -v num_threads="$2" '{printf "%.0f\n", $1/num_threads}')
    else
        echo $calculated_bytes
    fi
}
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
    if [ "${USE_CDN}" == true ]; then
        CDN_PATH="source.zhijie.online"
    else
        CDN_PATH="raw.githubusercontent.com/hezhijie0327"
    fi

    if [ ! -d "${DOCKER_PATH}/conf" ]; then
        mkdir -p "${DOCKER_PATH}/conf"
    fi

    if [ "${DOWNLOAD_CONFIG:-true}" == "true" ]; then
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/ZJDNS/main/unbound/unbound.conf" | sed "s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" > "${DOCKER_PATH}/conf/unbound.conf"

        if [ ! -d "${DOCKER_PATH}/work" ]; then
            mkdir -p "${DOCKER_PATH}/work"
        fi

        if [ "${NUM_THREADS}" != "" ]; then
            if [ "${NUM_THREADS}" == "auto" ]; then
                NUM_THREADS=$(grep -c ^processor /proc/cpuinfo)

                if [ "${ENABLE_FORK_OPERATION:-true}" == "false" ]; then
                    SLABS=$(echo $NUM_THREADS | awk '{printf "%.0f\n", 2^int(log($1-1)/log(2)+1)}')
                else
                    FORK_NUM_THREADS=$NUM_THREADS
                fi
            fi && sed -i "s/num-threads\: 1/num-threads\: ${NUM_THREADS:-1}/g;s/slabs: 1/slabs: ${SLABS:-1}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_DNSSEC}" == "false" ]; then
            sed -i "s/validator //g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_DNSSEC}" == "true" ] && [ "${ENABLE_DNSSEC_PERMISSIVE_MODE}" == "true" ]; then
            sed -i "s/val-permissive-mode\: no/val-permissive-mode\: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_ECS}" == "false" ]; then
            sed -i "s/subnetcache //g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_FORWARD}" == "true" ]; then
            sed -i "s/#+/  /g" "${DOCKER_PATH}/conf/unbound.conf"
            if [ "${ENABLE_FORWARD_CACHE}" == "false" ]; then
                sed -i "s/forward-no-cache: no/forward-no-cache: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
        else
            sed -i "/forward-zone:/d;/#+/d" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_RECURSIVE_DNS}" == "true" ]; then
            sed -i "s/forward-first: no/forward-first: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_IPV4}" == "false" ]; then
            sed -i "s/do-ip4\: yes/do-ip4\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_IPV6}" == "false" ]; then
            sed -i "s/do-ip6\: yes/do-ip6\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_IP64}" == "true" ]; then
            sed -i "s/do-nat64\: no/do-nat64\: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_LOGFILE}" == "true" ]; then
            sed -i "s/##/  /g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_RATELIMIT}" == "false" ]; then
            sed -i "s/ratelimit\: 1000/ratelimit\: 0/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_USE_CAPS_FOR_ID}" == "false" ]; then
            sed -i "s/use-caps-for-id\: yes/use-caps-for-id\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_PREFETCH}" == "false" ]; then
            sed -i "s/prefetch\: yes/prefetch\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_PREFETCH_KEY}" == "false" ]; then
            sed -i "s/prefetch-key\: yes/prefetch-key\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_SERVE_EXPIRED}" == "false" ]; then
            sed -i "s/serve-expired\: yes/serve-expired\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_SERVE_EXPIRED_TTL_RESET}" == "false" ]; then
            sed -i "s/serve-expired-ttl-reset\: yes/serve-expired-ttl-reset\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_SERVE_ORIGINAL_TTL}" == "true" ]; then
            sed -i "s/serve-original-ttl\: no/serve-original-ttl\: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${SERVE_EXPIRED_CLIENT_TIMEOUT:-0}" != "0" ]; then
            sed -i "s/serve-expired-client-timeout\: 0/serve-expired-client-timeout\: ${SERVE_EXPIRED_CLIENT_TIMEOUT}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${SERVE_EXPIRED_TTL:-0}" != "0" ]; then
            sed -i "s/serve-expired-ttl\: 0/serve-expired-ttl\: ${SERVE_EXPIRED_TTL}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${CACHE_SIZE_KEY:-4m}" != "" ]; then
            sed -i "s/key-cache-size: 4m/key-cache-size: $(CaculateCacheSize $CACHE_SIZE_KEY ${FORK_NUM_THREADS:-1})/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CACHE_SIZE_MSG:-4m}" != "" ]; then
            sed -i "s/msg-cache-size: 4m/msg-cache-size: $(CaculateCacheSize $CACHE_SIZE_MSG ${FORK_NUM_THREADS:-1})/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CACHE_SIZE_NEG:-1m}" != "" ]; then
            sed -i "s/neg-cache-size: 1m/neg-cache-size: $(CaculateCacheSize $CACHE_SIZE_NEG ${FORK_NUM_THREADS:-1})/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CACHE_SIZE_RRSET:-4m}" != "" ]; then
            sed -i "s/rrset-cache-size: 4m/rrset-cache-size: $(CaculateCacheSize $CACHE_SIZE_RRSET ${FORK_NUM_THREADS:-1})/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_REDIS_CACHE}" == "false" ]; then
            sed -i "/cachedb:/d;/#-/d;s/cachedb //g" "${DOCKER_PATH}/conf/unbound.conf"
        else
            sed -i "s/#-/  /g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_REDIS_CACHE_CHECK_WHEN_SERVE_EXPIRED}" == "false" ]; then
            sed -i "s/cachedb-check-when-serve-expired: yes/cachedb-check-when-serve-expired: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_LOGICAL_DB}" != "" ]; then
            sed -i "s/redis-logical-db: 0/redis-logical-db: ${CUSTOM_REDIS_LOGICAL_DB}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_SERVER_HOST}" != "" ]; then
            sed -i "s/redis-server-host: 127.0.0.1/redis-server-host: ${CUSTOM_REDIS_SERVER_HOST}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_SERVER_PASSWORD}" != "" ]; then
            sed -i "s/redis-server-password: ''/redis-server-password: '${CUSTOM_REDIS_SERVER_PASSWORD}'/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_SERVER_PATH}" != "" ]; then
            sed -i "s/redis-server-path: ''/redis-server-path: '${CUSTOM_REDIS_SERVER_PATH}'/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_REDIS_SERVER_PORT}" != "" ]; then
            sed -i "s/redis-server-port: 6379/redis-server-port: ${CUSTOM_REDIS_SERVER_PORT}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${CUSTOM_SECRET_SEED}" != "" ]; then
            sed -i "s/secret-seed: 'default'/secret-seed: '${CUSTOM_SECRET_SEED}'/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_REMOTE_CONTROL}" == "false" ]; then
            sed -i "/remote-control:/d;/#=/d" "${DOCKER_PATH}/conf/unbound.conf"
        else
            sed -i "s/#=/  /g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_UNENCRYPTED_DNS}" == "false" ]; then
            if [ "${ENABLE_HTTPS}" == "true" ] || [ "${ENABLE_TLS}" == "true" ]; then
                sed -i "s/    interface/#+  interface/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
        else
            if [ "${UNENCRYPTED_PORT:-3553}" != "3553" ]; then
                sed -i "s/port: 3553/port: ${UNENCRYPTED_PORT}/g;s/@3553/@${UNENCRYPTED_PORT}/g" "${DOCKER_PATH}/conf/unbound.conf"
            fi
        fi

        if [ "${CUSTOM_UPSTREAM[*]}" != "" ]; then
            SED_CUSTOM_UPSTREAM="" && for CUSTOM_UPSTREAM_TASK in "${!CUSTOM_UPSTREAM[@]}"; do
                SED_CUSTOM_UPSTREAM="${SED_CUSTOM_UPSTREAM}    forward-addr: ${CUSTOM_UPSTREAM[$CUSTOM_UPSTREAM_TASK]}\n"
            done && CUSTOM_UPSTREAM="${SED_CUSTOM_UPSTREAM%\\n}"

            sed -i "s/    forward-addr: 127.0.0.1@5533/${CUSTOM_UPSTREAM}/g;s/    forward-addr: 127.0.0.1@5535/${CUSTOM_UPSTREAM}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_TCP_UPSTREAM}" == "false" ]; then
            sed -i "s/tcp-upstream\: yes/tcp-upstream\: no/g;s/tls-upstream\: no/tls-upstream\: no/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_TLS_UPSTREAM}" == "true" ]; then
            sed -i "s/127.0.0.1@5533/127.0.0.1@5535/g;s/tcp-upstream\: yes/tcp-upstream\: no/g;s/tls-upstream\: no/tls-upstream\: yes/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ "${ENABLE_HTTPS}" == "true" ]; then
            sed -i "s/#@/  /g;s/https-port: 3353/https-port: ${HTTPS_PORT:-3353}/g;s/@3353/@${HTTPS_PORT:-3353}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi
        if [ "${ENABLE_TLS}" == "true" ]; then
            sed -i "s/#%/  /g;s/tls-port: 3533/tls-port: ${TLS_PORT:-3533}/g;s/@3533/@${TLS_PORT:-3533}/g" "${DOCKER_PATH}/conf/unbound.conf"
        fi

        if [ -f "${DOCKER_PATH}/conf/unbound.conf" ]; then
            sed -i "/#/d" "${DOCKER_PATH}/conf/unbound.conf"
        fi
    fi
}
# Create New Container
function CreateNewContainer() {
    docker run --name ${REPO} --net host --restart=always \
        -v /docker/ssl:/etc/unbound/cert:ro \
        -v ${DOCKER_PATH}/conf:/etc/unbound/conf \
        -v ${DOCKER_PATH}/work:/etc/unbound/work \
        -d ${OWNER}/${REPO}:${TAG} \
        -c "/etc/unbound/conf/unbound.conf" \
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
#Call DownloadConfiguration
DownloadConfiguration
# Call CreateNewContainer
CreateNewContainer
# Call CleanupExpiredImage
CleanupExpiredImage
