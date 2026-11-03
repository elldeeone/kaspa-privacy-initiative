# Integrated binding/state regression

The copied integration source passes all 14 compiled-binding tests and all 14 state-core tests in its own directory. Source identities are unchanged before/after. No guest execution, proving, native validation or chain claim follows from this check.

Attempt 1 failed before Cargo ran because systemd did not inherit the interactive Cargo PATH. Its runner, empty streams, source identities and journal are retained unchanged. Attempt 2 explicitly sets the toolchain PATH and passes.

The bounded service used two CPU equivalents, 3 GiB RAM, no swap allowance and offline Cargo/AF_UNIX sockets. Systemd reports 29.673 seconds wall, 57.072 seconds CPU, 974.1M displayed peak memory and zero swap. Test-binary hashes were recorded after the run, not independently before execution.
