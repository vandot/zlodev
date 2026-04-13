#!/bin/bash
# Helper script for demo recording — generates traffic for the TUI
sleep 5
curl -sk https://dev.lo/get > /dev/null
sleep 1
curl -sk -X POST -d '{"name":"zlodev"}' -H 'Content-Type: application/json' https://dev.lo/post > /dev/null
sleep 1
curl -sk https://dev.lo/headers > /dev/null
sleep 1
curl -sk https://dev.lo/ip > /dev/null
sleep 1
curl -sk -X PUT -d '{"status":"active"}' https://dev.lo/put > /dev/null
sleep 1
curl -sk https://dev.lo/user-agent > /dev/null
sleep 1
curl -sk -X DELETE https://dev.lo/delete > /dev/null
sleep 1
curl -sk -X PATCH -d '{"id":42}' https://dev.lo/patch > /dev/null
sleep 1
curl -sk https://dev.lo/status/201 > /dev/null
sleep 1
curl -sk https://dev.lo/status/404 > /dev/null
