# Pinned standard SoftSpoken build

The admitted source hashes and commits are in [DEPENDENCIES.json](DEPENDENCIES.json).
Extract MP-SPDZ, SimplestOT_C, libOTe and cryptoTools at those pins. Place libOTe
at `MP-SPDZ/deps/libOTe2` and cryptoTools in its `cryptoTools` subdirectory. Stage
the pinned coproto, macoro and function2 repositories under `dependency-sources`.
The GMP/libsodium development packages and libdivide header stay in the local
`prefix/usr`; no system install is required. Reuse the pinned mcl build.
Apply only `vendor-patches/mp-spdz-mutual-tls.patch` to MP-SPDZ.

Use a fresh source/build directory when changing these macros. MP-SPDZ Make
rules do not reliably rebuild every object when macro flags change. Old KOS
objects and binaries are retained separately and are never mixed into this tree.

Set `KPI_VENDOR` to the absolute fresh vendor root. `MP-SPDZ/CONFIG.mine` contains:

```make
CXX = g++
USE_KOS = 0
USE_LIBOTE2 = 1
USE_TUNGSTEN = 0
AVX_OT = 0
OPTIM = -O1
GDEBUG = -g0
MY_CFLAGS = -I$(KPI_VENDOR)/prefix/usr/include -I$(KPI_VENDOR)/prefix/usr/include/x86_64-linux-gnu -DNO_MIXED_CIRCUITS
MY_LDLIBS = -L$(KPI_VENDOR)/prefix/usr/lib/x86_64-linux-gnu -Wl,-rpath,$(KPI_VENDOR)/prefix/usr/lib/x86_64-linux-gnu
```

Substitute the absolute path for `$(KPI_VENDOR)` in that file. Do not enable
`INSECURE`, `NDEBUG` or secret debug output. Build libOTe through a parent CMake
project so its default standalone Release flags cannot silently disable asserts.
The parent `cmake-driver/CMakeLists.txt` is:

```cmake
cmake_minimum_required(VERSION 3.20)
project(kpi_pinned_libote LANGUAGES C CXX ASM)
set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "" FORCE)
set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "-O1 -g0" CACHE STRING "" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-O1 -g0" CACHE STRING "" FORCE)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
add_subdirectory("${KPI_VENDOR}/MP-SPDZ/deps/libOTe2" libOTe2)
```

Substitute the vendor path in `add_subdirectory`. The successful configure was:

```sh
cmake \
  -S \
  $KPI_VENDOR/cmake-driver \
  -B \
  $KPI_VENDOR/libote-build-02 \
  -DCMAKE_CXX_COMPILER=g++ \
  -DCMAKE_INSTALL_PREFIX=$KPI_VENDOR/MP-SPDZ/local \
  -DCMAKE_INSTALL_LIBDIR=lib \
  -DCMAKE_PREFIX_PATH=$KPI_VENDOR/prefix/usr \
  -DCMAKE_INCLUDE_PATH=$KPI_VENDOR/prefix/usr/include \
  -DCMAKE_LIBRARY_PATH=$KPI_VENDOR/prefix/usr/lib/x86_64-linux-gnu \
  -DENABLE_SOFTSPOKEN_OT=ON \
  -DENABLE_SILENTOT=ON \
  -DENABLE_SIMPLESTOT=ON \
  -DENABLE_SODIUM=ON \
  -DENABLE_RELIC=OFF \
  -DENABLE_BOOST=OFF \
  -DENABLE_OPENSSL=OFF \
  -DENABLE_SPAN_LITE=OFF \
  -DENABLE_PIC=ON \
  -DENABLE_PORTABLE_AES=ON \
  -DFETCH_AUTO=OFF \
  -DFETCH_COPROTO=ON \
  -DFETCH_BOOST=OFF \
  -DFETCH_LIBDIVIDE=OFF \
  -DFETCH_SODIUM=OFF \
  -DLIBOTE_BUILD_DIR=$KPI_VENDOR/libote-build-02/libOTe2 \
  -DCRYPTOTOOLS_BUILD_DIR=$KPI_VENDOR/libote-build-02/libOTe2/cryptoTools \
  -DOC_THIRDPARTY_INSTALL_PREFIX=$KPI_VENDOR/MP-SPDZ/local \
  -DOC_THIRDPARTY_HINT=$KPI_VENDOR/MP-SPDZ/local \
  -DOC_THIRDPARTY_CLONE_DIR=$KPI_VENDOR/dependency-sources \
  -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DSODIUM_MONTGOMERY=OFF
cmake --build "$KPI_VENDOR/libote-build-02" --target libOTe --parallel 6
```

`SODIUM_MONTGOMERY=OFF` selects the documented standard libsodium Ristretto path
for SimplestOT. The custom Montgomery noclamp extension is unavailable and not
selected by this build. It does not disable malicious SoftSpoken checks.

Stage the exact successfully built `liblibOTe.a`, `libcryptoTools.a`,
`libcoproto.a` and `libmacoro.a` in `MP-SPDZ/local/lib`. Stage their public headers
in `MP-SPDZ/local/include`, including the matching generated configuration headers
from that same build (cryptoTools uses `cryptoTools/Common/config.h`). Include
function2's headers. Verify no generated compile command contains `NDEBUG` or
`INSECURE`. Do not run upstream `build.py --install` afterward: it can select a
separate Release build and different worker count. `make -n` must show no such
recursion.

From `MP-SPDZ`, build fresh objects and the shared library:

```sh
make -j6 libSPDZ.so OT/BaseOT.o OT/OTExtension.o \
  OT/OTExtensionWithMatrix.o OT/BitDiagonal.o OT/OTTripleSetup.o \
  OT/MascotParams.o deps/SimplestOT_C/ref10/libSimplestOT.a
```

The successful build records, selected library hashes and configuration command
are preserved with [the functional evidence](evidence/2026-10-28-functional-toy/).
Then use `build.py` and `run_toy.py` as described in the README. This configuration
qualifies only the recorded public synthetic fixture, not a payment system or a
cryptographic audit.
