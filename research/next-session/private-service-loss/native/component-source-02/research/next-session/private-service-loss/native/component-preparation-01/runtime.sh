#!/bin/bash
set -euo pipefail
/usr/bin/python3 -B /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/private-cashout-native/test_helper.py >/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-service-loss/native/component-execution-01/helper-tests.log 2>&1
/usr/bin/node /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/private-cashout-native/test_adapter.mjs >/home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-service-loss/native/component-execution-01/transport-tests.log 2>&1
