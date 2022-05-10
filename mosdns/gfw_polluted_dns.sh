#!/bin/sh

GFW_DOMAIN="zh.wikipedia.org"
FAKE_DNS="11.45.1.4"
TOTAL_TIME="300"

rm -rf ./gfw_polluted_ipv*.txt

for (( i = 1; i <= ${TOTAL_TIME}; i++ )); do
    echo "$(dig @${FAKE_DNS} ${GFW_DOMAIN} +short A | cut -d "." -f 1-3).0/24" >> "./gfw_polluted_ipv4.tmp"
    echo "$(dig @${FAKE_DNS} ${GFW_DOMAIN} +short AAAA | cut -d ":" -f 1-3):0/112" >> "./gfw_polluted_ipv6.tmp"
done

cat "./gfw_polluted_ipv4.tmp"| sort | uniq > "./gfw_polluted_ipv4.txt"
cat "./gfw_polluted_ipv6.tmp" | sort | uniq > "./gfw_polluted_ipv6.txt"

rm -rf ./gfw_polluted_ipv*.tmp
