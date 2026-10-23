#!/bin/bash
set -euo pipefail
test "$(/usr/bin/sha256sum /app/node | /usr/bin/cut -d' ' -f1)" = d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c
/app/node --use-openssl-ca --version >/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-service-loss/native/transport-execution-01/node-version.log
test "$(/usr/bin/sha256sum /app/node | /usr/bin/cut -d' ' -f1)" = d1de76d8edf2fededf6f8b30d244e2c0529ac607923a018283b77e9c74bd932c
/app/node --use-openssl-ca /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/private-cashout-native/test_adapter.mjs >/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-service-loss/native/transport-execution-01/transport-tests.log 2>&1
