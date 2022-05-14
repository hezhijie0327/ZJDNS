#!/bin/sh

GFW_DOMAIN="zh.wikipedia.org"
FAKE_DNS="11.45.1.4"
GHPROXY_URL="https://ghproxy.com/"
TOTAL_TIME="300"

rm -rf "./POLLUTED.tmp" "./POLLUTED.txt"

curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/POLLUTED.txt" > "./POLLUTED.tmp"

for (( i = 1; i <= ${TOTAL_TIME}; i++ )); do
    echo "$(dig @${FAKE_DNS} ${GFW_DOMAIN} +short A | cut -d "." -f 1-3).0/24" >> "./POLLUTED.tmp"
done

cat "./POLLUTED.tmp"| sort | uniq > "./POLLUTED.txt"

rm -rf "./POLLUTED.tmp"
