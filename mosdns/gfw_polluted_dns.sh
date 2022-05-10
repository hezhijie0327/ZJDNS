#!/bin/sh

GFW_DOMAIN="zh.wikipedia.org"
FAKE_DNS="11.45.1.4"
GHPROXY_URL="https://ghproxy.com/"
TOTAL_TIME="300"

rm -rf ./gfw_polluted_ipv*.txt

curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/gfw_polluted_ipv4.txt" > "./gfw_polluted_ipv4.tmp"
curl -s --connect-timeout 15 "${GHPROXY_URL}https://raw.githubusercontent.com/hezhijie0327/CMA_DNS/main/mosdns/gfw_polluted_ipv6.txt" > "./gfw_polluted_ipv6.tmp"

for (( i = 1; i <= ${TOTAL_TIME}; i++ )); do
    echo "$(dig @${FAKE_DNS} ${GFW_DOMAIN} +short A | cut -d "." -f 1-3).0/24" >> "./gfw_polluted_ipv4.tmp"
    echo "$(dig @${FAKE_DNS} ${GFW_DOMAIN} +short AAAA | cut -d ":" -f 1-3):0/112" >> "./gfw_polluted_ipv6.tmp"
done

cat "./gfw_polluted_ipv4.tmp"| sort | uniq > "./gfw_polluted_ipv4.txt"
cat "./gfw_polluted_ipv6.tmp" | sort | uniq > "./gfw_polluted_ipv6.txt"

rm -rf ./gfw_polluted_ipv*.tmp
