#!/bin/bash

# Parameter
OWNER="hezhijie0327"
REPO="smartdns"
TAG="latest"
DOCKER_PATH="/docker/smartdns"

CURL_OPTION=""
DOWNLOAD_CONFIG="" # false, true
USE_CDN="true"

CNIPDB_SOURCE="" # bgp, dbip, geolite2, iana, ip2location, ipinfoio, ipipdotnet, iptoasn, vxlink, zjdb

ENABLE_AUDIT_LOG="" # false, true
LOG_LEVEL="" # off, fatal, error, warn, notice, info, debug

SAVE_AUDIT_TO_FILE="" # false, true
SAVE_LOG_TO_FILE="" # false, true

SERVER_NAME="$(hostname)" # smartdns, $(hostname)

CACHE_CHECKPOINT_TIME="" # 300, 600, 900
CACHE_PERSIST="" # false, true
CACHE_SIZE="" # -1 (Auto), 0 (None), 4096

EDNS_ADDR="" # auto, 127.0.0.1, ::1
EDNS_ADDR_TYPE="" # A, AAAA

MAX_REPLY_IP_NUM="" # 1 - 16 (MAX)
RESPONSE_MODE="" # first-ping, fastest-ip, fastest-response
SPEED_CHECK_MODE="" # none, ping, tcp:port

DUALSTACK_IP_ALLOW_FORCE_AAAA="" # false, true
DUALSTACK_IP_SELECTION="" # false, true

PREFETCH_DOMAIN="" # false, true

SERVE_EXPIRED="" # false, true

FORCE_AAAA_SOA="" # false, true

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
        curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/ZJDNS/main/smartdns/smartdns.conf" | sed "s/fullchain\.cer/${SSL_CERT/./\\.}/g;s/zhijie\.online\.key/${SSL_KEY/./\\.}/g" | sort | uniq > "${DOCKER_PATH}/conf/smartdns.conf"

        if [ "${ENABLE_AUDIT_LOG}" == "true" ]; then
            sed -i "s/audit-enable no/audit-enable yes/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${LOG_LEVEL}" != "" ]; then
            sed -i "s/log-level error/log-level ${LOG_LEVEL}/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${SAVE_AUDIT_TO_FILE}" == "true" ]; then
            sed -i "s/audit-console yes/audit-console no/g" "${DOCKER_PATH}/conf/smartdns.conf"
        else
            sed -i "s/audit-file/#audit-file/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${SAVE_LOG_TO_FILE}" == "true" ]; then
            sed -i "s/log-console yes/log-console no/g" "${DOCKER_PATH}/conf/smartdns.conf"
        else
            sed -i "s/log-file/#log-file/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${SERVER_NAME}" != "" ]; then
            sed -i "s/server-name smartdns/server-name ${SERVER_NAME}/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${CACHE_CHECKPOINT_TIME}" != "" ]; then
            sed -i "s/cache-checkpoint-time 300/cache-checkpoint-time ${CACHE_CHECKPOINT_TIME}/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${CACHE_PERSIST}" == "false" ]; then
            sed -i "s/cache-persist yes/cache-persist no/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${CACHE_SIZE}" != "" ]; then
            if [ "${CACHE_SIZE}" == "-1" ]; then
                sed -i "/cache-size 4096/d" "${DOCKER_PATH}/conf/smartdns.conf"
            else
                sed -i "s/cache-size 4096/cache-size ${CACHE_SIZE}/g" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        fi

        if [ "${EDNS_ADDR}" != "" ]; then
            if [ "${EDNS_ADDR_TYPE:-A}" != "A" ]; then
                EDNS_CLIENT_SUBNET="48"
            fi && sed -i "s|edns-client-subnet 127.0.0.1/24|edns-client-subnet $(StaticIP=${EDNS_ADDR} && Type=${EDNS_ADDR_TYPE:-A} && GetWANIP)/${EDNS_CLIENT_SUBNET:-24}|g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${MAX_REPLY_IP_NUM}" != "" ]; then
            sed -i "s/max-reply-ip-num 1/max-reply-ip-num ${MAX_REPLY_IP_NUM}/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${RESPONSE_MODE}" != "" ]; then
            sed -i "s/response-mode fastest-response/response-mode ${RESPONSE_MODE}/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${SPEED_CHECK_MODE}" != "" ]; then
            sed -i "s/speed-check-mode ping,tcp:443,tcp:80/speed-check-mode ${SPEED_CHECK_MODE}/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${DUALSTACK_IP_ALLOW_FORCE_AAAA}" == "true" ]; then
            sed -i "s/dualstack-ip-allow-force-AAAA no/dualstack-ip-allow-force-AAAA yes/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${DUALSTACK_IP_SELECTION}" == "true" ]; then
            sed -i "s/dualstack-ip-selection no/dualstack-ip-selection yes/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${PREFETCH_DOMAIN}" == "false" ]; then
            sed -i "s/prefetch-domain yes/prefetch-domain no/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${SERVE_EXPIRED}" == "false" ]; then
            sed -i "s/serve-expired yes/serve-expired no/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${FORCE_AAAA_SOA}" == "true" ]; then
            sed -i "s/force-AAAA-SOA no/force-AAAA-SOA yes/g" "${DOCKER_PATH}/conf/smartdns.conf"
        fi

        if [ "${PREFER_REMOTE_UPSTREAM}" == "true" ]; then
            sed -i "s/-proxy remote_proxy/-blacklist-ip -proxy remote_proxy/g;s/-blacklist-ip -blacklist-ip/-blacklist-ip/g;s/-whitelist-ip //g" "${DOCKER_PATH}/conf/smartdns.conf" && SED_CNIPDB="blacklist"
        else
            SED_CNIPDB="whitelist"
        fi

        if [ "${ENABLE_LOCAL_UPSTREAM}" != "false" ]; then
            if [ "${ENABLE_LOCAL_UPSTREAM}" == "ipv4" ]; then
                sed -i "/local_ipv6/d" "${DOCKER_PATH}/conf/smartdns.conf"
            elif [ "${ENABLE_LOCAL_UPSTREAM}" == "ipv6" ]; then
                sed -i "/local_ipv4/d" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        else
            sed -i "/local_ipv/d" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
        if [ "${ENABLE_REMOTE_UPSTREAM}" != "false" ]; then
            if [ "${ENABLE_REMOTE_UPSTREAM}" == "ipv4" ]; then
                sed -i "/remote_ipv6/d" "${DOCKER_PATH}/conf/smartdns.conf"
            elif [ "${ENABLE_REMOTE_UPSTREAM}" == "ipv6" ]; then
                sed -i "/remote_ipv4/d" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        else
            sed -i "/remote_ipv/d;s/-ignore-ip //g;s/-whitelist-ip //g" "${DOCKER_PATH}/conf/smartdns.conf"
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
                sed -i "s/bind \[::\]:5335/bind \[::\]:${UNENCRYPTED_PORT}/g;s/bind-tcp \[::\]:5335/bind-tcp \[::\]:${UNENCRYPTED_PORT}/g" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        fi
        if [ "${ENABLE_TLS}" == "false" ]; then
            sed -i "/bind-cert/d;/bind-tls/d" "${DOCKER_PATH}/conf/smartdns.conf"
        else
            if [ "${TLS_PORT:-5355}" != "5355" ]; then
                sed -i "s/bind-tls \[::\]:5355/bind-tls \[::\]:${TLS_PORT}/g" "${DOCKER_PATH}/conf/smartdns.conf"
            fi
        fi

        if [ -f "${DOCKER_PATH}/conf/smartdns.conf" ]; then
            sed -i "/#/d;/^$/d" "${DOCKER_PATH}/conf/smartdns.conf"
        fi
    fi

    if [ ! -d "${DOCKER_PATH}/data" ]; then
        mkdir -p "${DOCKER_PATH}/data"
    fi && curl ${CURL_OPTION:--4 -s --connect-timeout 15} "https://${CDN_PATH}/CNIPDb/main/cnipdb_${CNIPDB_SOURCE:-geolite2}/country_ipv4_6.txt" | sed "s/^/${SED_CNIPDB}-ip /g" > "${DOCKER_PATH}/data/GeoIP_CNIPDb.conf"
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
        -v ${DOCKER_PATH}/data:/etc/smartdns/data \
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
