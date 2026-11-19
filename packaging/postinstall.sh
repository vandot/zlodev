#!/bin/sh
# Let zlodev bind ports 53, 80 and 443 without root.
if command -v setcap >/dev/null 2>&1; then
    setcap cap_net_bind_service=+eip /usr/bin/zlodev || echo "zlodev: setcap failed; run zlodev with sudo"
else
    echo "zlodev: setcap not found; run zlodev with sudo"
fi
echo "Run 'zlodev install' once to set up the CA and DNS."
