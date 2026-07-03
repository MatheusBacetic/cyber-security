#!/bin/bash

read -r ALERT_JSON

SRCIP=$(echo "$ALERT_JSON" | /var/ossec/framework/python/bin/python3 -c '
import json
import sys

try:
    alert = json.load(sys.stdin)
    print(alert["parameters"]["alert"]["data"]["srcip"])
except Exception:
    sys.exit(1)
')

# Safety allowlist: never block these addresses
case "$SRCIP" in
    ""|"127.0.0.1"|"::1"|"192.168.100.10")
        exit 0
        ;;
esac

# Accept IPv4 only and block it temporarily for 10 minutes
if [[ "$SRCIP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    /usr/sbin/nft add element inet wazuh_ar blocked_ips { "$SRCIP" timeout 10m }
fi

exit 0