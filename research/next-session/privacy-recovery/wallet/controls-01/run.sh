#!/bin/bash
set -euo pipefail
exec /usr/bin/bwrap --unshare-all --die-with-parent --new-session --clearenv \
 --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 \
 --ro-bind /etc/alternatives /etc/alternatives --proc /proc --dev /dev --tmpfs /tmp \
 --dir /workspace --dir /workspace/poc --dir /workspace/poc/future-recipient \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/independent-recovery /workspace/poc/independent-recovery \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/poc/future-recipient/v2 /workspace/poc/future-recipient/v2 \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/execution-01/private/transaction.json /workspace/research/next-session/private-integration/lifecycle/execution-01/private/transaction.json \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/private-integration/lifecycle/setup-01/verification-key.bin /workspace/research/next-session/private-integration/lifecycle/setup-01/verification-key.bin \
 --ro-bind /home/luke/projects/kpi-intensive-2026-10-22/recipient-target/debug/kpi-future-recipient-crypto /recipient-target/debug/kpi-future-recipient-crypto \
 --bind /home/luke/projects/kpi-intensive-2026-10-22/continuation/research/next-session/privacy-recovery/wallet/controls-01 /wallet-out --setenv PATH /usr/bin:/bin \
 --chdir /workspace/poc/independent-recovery \
 /usr/bin/time -v -o /wallet-out/resources.log /usr/bin/python3 -B -m unittest -v test_wallet
