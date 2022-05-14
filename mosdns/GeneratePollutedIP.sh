#!/bin/sh

GFW_DOMAIN="zh.wikipedia.org"
FAKE_DNS="11.45.1.4"
GHPROXY_URL="https://ghproxy.com/"
TOTAL_TIME="300"

rm -rf "./GFW_Polluted_IP.tmp" "./GFW_Polluted_IP.txt"

curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/GFW_Polluted_IP.txt" > "./GFW_Polluted_IP.tmp"

for (( i = 1; i <= ${TOTAL_TIME}; i++ )); do
    echo "$(dig @${FAKE_DNS} ${GFW_DOMAIN} +short A | cut -d "." -f 1-3).0/24" >> "./GFW_Polluted_IP.tmp"
done

cat "./GFW_Polluted_IP.tmp"| sort | uniq > "./GFW_Polluted_IP.txt"

rm -rf "./GFW_Polluted_IP.tmp"
