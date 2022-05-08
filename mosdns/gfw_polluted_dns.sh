#!/bin/sh

GFW_DOMAIN="zh.wikipedia.org"
FAKE_DNS="11.45.1.4"
TOTAL_TIME="900"

rm -rf ./gfw_polluted_ipv*.txt && for (( i = 1; i <= ${TOTAL_TIME}; i++)); do
    echo "$(dig @${FAKE_DNS} ${GFW_DOMAIN} +short A)/24" >> "./gfw_polluted_ipv4.tmp"
    echo "$(dig @${FAKE_DNS} ${GFW_DOMAIN} +short AAAA)/112" >> "./gfw_polluted_ipv6.tmp"
done && cat "./gfw_polluted_ipv4.tmp" | sort | uniq > "./gfw_polluted_ipv4.txt" && cat "./gfw_polluted_ipv6.tmp" | sort | uniq > "./gfw_polluted_ipv6.txt"
