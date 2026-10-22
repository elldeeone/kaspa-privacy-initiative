#!/bin/bash
set -euo pipefail
for s7_check_bin in kpi_s7_pair_native_check kpi_s7_ordinary_spend_check; do
  /bin/bash /home/luke/projects/kpi-intensive-2026-10-22/native-runtime/build-s7-bin.sh "$s7_check_bin"
done
