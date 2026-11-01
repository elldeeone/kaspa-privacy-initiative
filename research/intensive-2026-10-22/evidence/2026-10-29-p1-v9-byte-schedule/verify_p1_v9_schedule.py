#!/usr/bin/env python3
"""Recompute the finite typed C03 schedule; never mint an FD bound."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path
import re
import struct


HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
RECEIPT = HERE / "P1-V9-TYPED-SCHEDULE.json"
HISTOGRAM = HERE / "site11-width-histogram.txt"

SITE_NAMES = {
    1: "owner-ddnnt-random-v",
    2: "owner-ddnnt-product-u",
    3: "owner-ddnnt-triple-s",
    4: "owner-ddnnt-triple-r",
    5: "owner-ddnnt-triple-w",
    6: "owner-derived-input",
    7: "trace-witness-random-bit",
    8: "trace-bit-add-generate",
    9: "trace-bit-add-propagate",
    10: "trace-bit-add-finalize",
    11: "trace-witness-buffered-product",
    12: "trace-witness-nonzero-accumulate",
    13: "trace-witness-nonzero-square",
    14: "trace-witness-reduction",
    15: "financial-assignment-equality",
    16: "financial-assignment-residual",
    17: "financial-assignment-nonzero-accumulate",
    18: "financial-assignment-nonzero-square",
    19: "streamed-h-product",
    20: "financial-proof-mask-r",
    21: "financial-proof-mask-s",
    22: "beaver-triple",
}

WIDTH_SCHEDULES = {
    1: "([4096]*643+[1681])*3",
    2: "([4096]*643+[1681])*3",
    3: "([4096]*643+[1681])*3",
    4: "([4096]*643+[1681])*3",
    5: "([4096]*643+[1681])*3",
    6: "[2635409]*3",
    7: "[1]*768",
    12: "[33896]*100",
    13: "[33896]*253",
    16: "[4096]*3196+[2213]",
    17: "[1]*100",
    18: "[1]*253",
    19: "[4096]*4096",
    20: "[1]",
    21: "[1]",
    22: "[6]",
}

ORDERED_WIDTH_SHA256 = {
    1: "3466f734781d5f90d1ff9b8716a4a72336f3db8fe22399a6dbfd52c94cfaf43b",
    2: "3466f734781d5f90d1ff9b8716a4a72336f3db8fe22399a6dbfd52c94cfaf43b",
    3: "3466f734781d5f90d1ff9b8716a4a72336f3db8fe22399a6dbfd52c94cfaf43b",
    4: "3466f734781d5f90d1ff9b8716a4a72336f3db8fe22399a6dbfd52c94cfaf43b",
    5: "3466f734781d5f90d1ff9b8716a4a72336f3db8fe22399a6dbfd52c94cfaf43b",
    6: "9c450681e8ca7e83b669281f0e6eb525a7d56665a577c2ce294a49890d29e477",
    7: "c980da6ab553b567b7d102562b1bf5ee6a5e31bfef1465b9e8e6746d2cff27a0",
    8: "ea3b780cd462ba521158e206ea5b4eee8dd58ed9c84c6d1dd9f9b3290ce1b049",
    9: "58fdcd397a42e5ca8d2a02a5a9e2f497f79e655f732862bbc8ed62ff4478e5f0",
    10: "e1af001aa3817ce40dd5bec7df81620aa520e911bc5ff1551b8c0610b252ba9b",
    11: "0f4b6393ebd9a5ed555b7f8b6b58a21cdb5ad173d6410d08b8a44683d42a94c8",
    12: "f5bb63329b9b26a3c27ba09c288860f5e95e0467ce6177d957a78dcdc6d82426",
    13: "e555b0557a0e3b63a092fa77e8a84fe791a0647c4611e14f62de1d0ba287ee7e",
    14: "72dcf03b22785c3098f3877d78e2115c9257189b23e30e90b5eb341fc95c46c2",
    16: "a33b9ebdf6078b4346329ba7866b3ed9cc59a946326e2f7b53a4394af4688658",
    17: "04b0963380cfe1b121454d4b6f6e8978dec5e32777aabf0ca847737955b4f77d",
    18: "542f3d9f6917ff2a861e0373fee997b1e805cce5ab729d3e6408ab1a5fcc7b1e",
    19: "235ad704bc2510d7108ada65f1d3c8d786caca5c1bffcd0a8f8e8bfaf7c6686b",
    20: "cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50",
    21: "cd2662154e6d76b2b2b92e70c0cac3ccf534f9b74eb5b89819ec509083d00a50",
    22: "14ac577cdb2ef6d986078b4054cc9893a9a14a16dbb0d8f37b89167c1f1aacdf",
}

HISTOGRAM_SHA256 = {
    8: "6e7eb91395ce7c20b1623eaaefc4d003933d095a8e4c2d444e50d91c4b92e855",
    9: "a5c9b6b27dceb48d4af28fa938105efc1685787b9199eb1601dca83a0386fdc4",
    10: "e36be00fac80fac1229e80d953263b8a506151a4f3a0e0c9a2ffe90c8201ccd1",
}

SOURCE_PATHS = {
    "poc/local-private-payment/mpc-prover/p1_capture_stream.hpp",
    "poc/local-private-payment/mpc-prover/p1_capture_stream.cpp",
    "poc/local-private-payment/mpc-prover/p1_scalar_capture_manifest.hpp",
    "poc/local-private-payment/mpc-prover/p1_capture_seams.cpp",
    "poc/local-private-payment/mpc-prover/p1_capturing_player.cpp",
    "poc/local-private-payment/mpc-prover/auth_field.cpp",
    "poc/local-private-payment/mpc-prover/owner_inputs_active.cpp",
    "poc/local-private-payment/mpc-prover/owner_input_ddnnt.cpp",
    "poc/local-private-payment/mpc-prover/trace/trace_witness.hpp",
    "poc/local-private-payment/mpc-prover/trace/trace_witness.cpp",
    "poc/local-private-payment/mpc-prover/trace/bit_add.hpp",
    "poc/local-private-payment/mpc-prover/financial/registered_construction.cpp",
    "poc/local-private-payment/mpc-prover/financial/registered_role_child_program.cpp",
    "poc/local-private-payment/mpc-prover/financial/registered_p1_context.cpp",
    "poc/local-private-payment/mpc-prover/financial/financial_assignment.cpp",
    "poc/local-private-payment/mpc-prover/financial/streamed_h_map.cpp",
    "poc/local-private-payment/mpc-prover/financial/financial_prover.cpp",
    "poc/local-private-payment/mpc-prover/auth_groups.cpp",
    "poc/local-private-payment/mpc-prover/financial/financial_release.cpp",
    "poc/local-private-payment/mpc-prover/financial/baseline_owner_effects_recipe_bridge.cpp",
    "poc/local-private-payment/private_batch_trial/privacy_selected_producer_byte_schedule_authority.hpp",
    "poc/local-private-payment/private_batch_trial/privacy_selected_producer_byte_schedule_authority.cpp",
    ".local/mpc-prover-softspoken-vendor/SOURCE-SELECTION.json",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/Protocols/ProtocolSetup.h",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/Protocols/ProtocolSet.h",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/Protocols/MascotPrep.h",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/Protocols/MascotPrep.hpp",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/OT/MascotMacKey.hpp",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/OT/NPartyTripleGenerator.hpp",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/OT/OTExtensionWithMatrix.cpp",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/Networking/Player.cpp",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/Networking/Player.h",
    ".local/mpc-prover-softspoken-vendor/MP-SPDZ/Processor/BaseMachine.h",
}

MISSING_BOUND_REASONS = [
    "KPI_REGISTERED_FINANCIAL_CONFIGURED is 0 and no selected registered main or schedule minter exists",
    "the exact accepted-head historical-nullifier count H is not bound into a pre-fork byte-schedule authority",
    "the exact ordered MP-SPDZ peer event schedule T is not derived or bound",
    "Mascot-Secrets valid-cache versus regeneration changes setup traffic",
    "SoftSpoken versus KOS and softspoken parameters are not part of a selected immutable execution preimage",
    "preprocessing buffer and OnlineOptions state are not represented by the current RunBinding",
    "an empirical prior-run size or operational abort cap is not a protocol upper bound",
]

FUTURE_AUTHORITY_MINIMUM = [
    "RunBinding trial attempt cohort round classification and fixed FD",
    "accepted-head identity and exact H",
    "trace model query scalar-manifest build and selected-main identities",
    "owner count width and multiplication batch",
    "per-site ordered-width digest calls elements share-chunks and wire bytes",
    "field group terminal and owner-frame schedule",
    "immutable OnlineOptions SoftSpoken/KOS and Mascot-Secrets freshness/cache policy",
    "ordered peer-event digest and exact peer logical-message chunk payload and wire totals",
    "final v9 logical-message chunk and byte totals",
    "one-shot split to pre-fork archive reservation and capture-side compare-before-END residuals",
]


class ReceiptError(RuntimeError):
    pass


def need(value: bool, label: str) -> None:
    if not value:
        raise ReceiptError(label)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def width_digest(widths: list[int]) -> str:
    digest = hashlib.sha256()
    for width in widths:
        need(0 < width < 1 << 64, "width-range")
        digest.update(struct.pack(">Q", width))
    return digest.hexdigest()


def scalar_metrics(widths: list[int]) -> dict[str, int]:
    chunks = sum((width + 2047) // 2048 for width in widths)
    elements = sum(widths)
    return {
        "calls": len(widths),
        "elements": elements,
        "share_chunks": chunks,
        "wire_bytes": 128 * len(widths) + 64 * elements + 224 * chunks,
    }


def histogram_metrics(raw: dict[str, int]) -> dict[str, int]:
    calls = 0
    elements = 0
    chunks = 0
    for encoded, count in raw.items():
        width = int(encoded)
        need(str(width) == encoded and width > 0 and type(count) is int and count > 0,
             "histogram-canonical")
        calls += count
        elements += width * count
        chunks += ((width + 2047) // 2048) * count
    return {
        "calls": calls,
        "elements": elements,
        "share_chunks": chunks,
        "wire_bytes": 128 * calls + 64 * elements + 224 * chunks,
    }


def histogram_digest(raw: dict[str, int]) -> str:
    histogram_metrics(raw)
    canonical = "".join(
        f"{int(encoded)}:{raw[encoded]}\n"
        for encoded in sorted(raw, key=int)
    ).encode("ascii")
    return sha256_bytes(canonical)


def generated_widths(site: int) -> list[int] | None:
    owner = ([4096] * 643 + [1681]) * 3
    return {
        1: owner, 2: owner, 3: owner, 4: owner, 5: owner,
        6: [2635409] * 3,
        7: [1] * 768,
        12: [33896] * 100,
        13: [33896] * 253,
        14: [16948, 8474, 4237, 2118, 1059, 530, 265, 132,
             66, 33, 17, 8, 4, 2, 1, 1],
        16: [4096] * 3196 + [2213],
        17: [1] * 100,
        18: [1] * 253,
        19: [4096] * 4096,
        20: [1], 21: [1], 22: [6],
    }.get(site)


def parse_site11(path: Path) -> tuple[dict[str, int], str]:
    raw = path.read_bytes()
    lines = raw.decode("ascii").splitlines()
    need(len(lines) == 570, "site11-line-count")
    match = re.fullmatch(
        r"total=(\d+) muls=(\d+) calls=(\d+) elements=(\d+) "
        r"chunks=(\d+) wire=(\d+) sha256_be64_widths=([0-9a-f]{64})",
        lines[0])
    need(match is not None, "site11-summary-grammar")
    histogram: dict[str, int] = {}
    previous = 0
    for line in lines[1:]:
        width_text, separator, count_text = line.partition(":")
        need(separator == ":" and width_text.isdigit() and count_text.isdigit(),
             "site11-row-grammar")
        width, count = int(width_text), int(count_text)
        need(width > previous and count > 0, "site11-order-or-count")
        histogram[width_text] = count
        previous = width
    metrics = histogram_metrics(histogram)
    need(metrics == {
        "calls": int(match.group(3)),
        "elements": int(match.group(4)),
        "share_chunks": int(match.group(5)),
        "wire_bytes": int(match.group(6)),
    }, "site11-summary-metrics")
    need(int(match.group(1)) == 15474590 and
         int(match.group(2)) == metrics["elements"], "site11-trace-counts")
    return metrics, match.group(7)


def wire(payload: int) -> int:
    need(type(payload) is int and payload >= 0, "payload-range")
    chunks = max(1, (payload + 65535) // 65536)
    return payload + 112 * chunks


def exact_keys(value: dict, expected: set[str], label: str) -> None:
    need(type(value) is dict and set(value) == expected, label + "-keys")


def verify_receipt(receipt: dict, *, check_sources: bool = True,
                   check_trace: bool = True) -> None:
    exact_keys(receipt, {
        "schema", "created_utc", "status", "authorizing",
        "p1_capture_configured", "fd23_bound", "fd28_bound", "scope",
        "source_pins", "framing", "scalar_sites", "fixed_scalar_excluding_H",
        "owner_raw_frames", "fixed_non_scalar_lanes", "field_openings",
        "symbolic_totals", "missing_bound_reasons", "future_authority_minimum",
    }, "receipt")
    need(receipt["schema"] ==
         "kpb-p1-v9-nonauthorizing-byte-schedule-receipt/v1" and
         receipt["status"] == "TYPED_SCHEDULE_EXACT_FD23_FD28_MISSING" and
         receipt["authorizing"] is False and
         receipt["p1_capture_configured"] is False and
         receipt["fd23_bound"] == receipt["fd28_bound"] == "MISSING",
         "nonauthorizing-boundary")

    need(receipt["scope"] ==
         "selected-source-shape-only-no-runnable-selected-driver",
         "scope")

    pins = receipt["source_pins"]
    exact_keys(pins, {
        "repo_base_commit", "mp_spdz_commit", "scalar_capture_manifest_sha256",
        "trace_container_sha256", "trace_canonical_sha256",
        "trace_canonical_bytes", "trace_operations", "trace_model_variables",
        "trace_assert_zero", "model_constraints", "files",
    }, "source-pins")
    need(type(pins["files"]) is dict and set(pins["files"]) == SOURCE_PATHS,
         "source-path-set")
    need(pins["trace_canonical_sha256"] ==
         "4c3dec7c553f66e45775bff2c950417060980cf443ab83a2d198587fc604808e" and
         pins["repo_base_commit"] ==
         "b58de1a182347c4223ebe84f92bb0bdd6c88d003" and
         pins["mp_spdz_commit"] ==
         "113c4e47dd94bca9ecab029d2f0abe649bea5c52" and
         pins["trace_container_sha256"] ==
         "0edbd4f22706d54a56ec5a670a2cf89f7075dd286130b3f64dbc73767cdef95c" and
         pins["trace_canonical_bytes"] == 2576450912 and
         pins["trace_operations"] == 15474590 and
         pins["trace_model_variables"] == 12949821 and
         pins["trace_assert_zero"] == 33896 and
         pins["model_constraints"] == 13093029 and
         pins["scalar_capture_manifest_sha256"] ==
         "5e6903569bc71cbfb5549b369b79a19ecda6686dc4ab25fca0d161c6e1527b6b",
         "source-identity")

    framing = receipt["framing"]
    exact_keys(framing, {
        "header_bytes", "max_chunk_payload_bytes", "wire_formula",
        "scalar_call_formula", "scalar_logical_messages_per_call",
        "selected_scalar_site_bitmap_hex",
    }, "framing")
    need(framing == {
        "header_bytes": 112,
        "max_chunk_payload_bytes": 65536,
        "wire_formula": "W(p)=p+112*max(1,ceil(p/65536))",
        "scalar_call_formula": "S(n)=128+64*n+224*ceil(n/2048)",
        "scalar_logical_messages_per_call": 3,
        "selected_scalar_site_bitmap_hex": "0x3fffff",
    },
         "framing")

    histogram_hash = sha256_path(HISTOGRAM)
    site11_metrics, site11_ordered_hash = parse_site11(HISTOGRAM)
    sites = receipt["scalar_sites"]
    need(type(sites) is list and len(sites) == 22 and
         [row["site"] for row in sites] == list(range(1, 23)), "site-set")

    fixed = {"calls": 0, "elements": 0, "share_chunks": 0,
             "wire_bytes": 0}
    for row in sites:
        site = row["site"]
        need(row.get("name") == SITE_NAMES[site], f"site{site}-name")
        if site == 15:
            exact_keys(row, {
                "site", "name", "symbolic", "width_generator", "per_H",
            }, "site15")
            need(row["symbolic"] == "H" and
                 row["width_generator"] ==
                 "for owner=0..2, for old=0..H-1: [128,64,32,16,8,4,2,1]" and
                 row["per_H"] == {
                "calls": 24, "elements": 765, "share_chunks": 24,
                "wire_bytes": 57408,
            }, "site15")
            continue
        widths = generated_widths(site)
        if widths is not None:
            if site == 14:
                exact_keys(row, {
                    "site", "name", "calls", "elements", "share_chunks",
                    "wire_bytes", "widths", "ordered_width_sha256",
                }, "site14")
                need(row["widths"] == widths, "site14-widths")
            else:
                exact_keys(row, {
                    "site", "name", "calls", "elements", "share_chunks",
                    "wire_bytes", "width_schedule", "ordered_width_sha256",
                }, f"site{site}")
                need(row["width_schedule"] == WIDTH_SCHEDULES[site],
                     f"site{site}-width-schedule")
            metrics = scalar_metrics(widths)
            need(width_digest(widths) == ORDERED_WIDTH_SHA256[site] and
                 row["ordered_width_sha256"] == ORDERED_WIDTH_SHA256[site],
                 f"site{site}-ordered-hash")
        elif site in (8, 9, 10):
            exact_keys(row, {
                "site", "name", "calls", "elements", "share_chunks",
                "wire_bytes", "width_histogram", "width_histogram_sha256",
                "ordered_width_sha256",
            }, f"site{site}")
            metrics = histogram_metrics(row["width_histogram"])
            need(histogram_digest(row["width_histogram"]) ==
                 HISTOGRAM_SHA256[site] and
                 row["width_histogram_sha256"] == HISTOGRAM_SHA256[site] and
                 row["ordered_width_sha256"] == ORDERED_WIDTH_SHA256[site],
                 f"site{site}-histogram-or-order-hash")
        elif site == 11:
            exact_keys(row, {
                "site", "name", "calls", "elements", "share_chunks",
                "wire_bytes", "width_histogram_file",
                "width_histogram_file_sha256", "ordered_width_sha256",
            }, "site11")
            metrics = site11_metrics
            need(row["width_histogram_file"] == HISTOGRAM.name and
                 histogram_hash ==
                 "1e1777549364731f03e51feb1a13b8cb4666fba6a4fde62293e37776e553a0af" and
                 row["width_histogram_file_sha256"] == histogram_hash and
                 site11_ordered_hash == ORDERED_WIDTH_SHA256[11] and
                 row["ordered_width_sha256"] == ORDERED_WIDTH_SHA256[11],
                 "site11-hashes")
        else:
            raise ReceiptError(f"site{site}-unhandled")
        need(all(row[key] == value for key, value in metrics.items()),
             f"site{site}-metrics")
        for key in fixed:
            fixed[key] += metrics[key]

    exact_keys(receipt["fixed_scalar_excluding_H"], {
        "calls", "elements", "share_chunks", "logical_messages",
        "c03_records", "wire_bytes",
    }, "fixed-scalar")
    expected_fixed = dict(receipt["fixed_scalar_excluding_H"])
    logical = expected_fixed.pop("logical_messages")
    records = expected_fixed.pop("c03_records")
    need(fixed == expected_fixed and logical == 3 * fixed["calls"] and
         records == fixed["calls"] + 2 * fixed["share_chunks"],
         "fixed-scalar-total")

    owner = receipt["owner_raw_frames"]
    exact_keys(owner, {
        "owner_count", "values_per_owner",
        "preprocessing_payload_bytes_per_owner",
        "preprocessing_chunks_per_owner", "preprocessing_wire_bytes_per_owner",
        "offset_payload_bytes_per_owner", "offset_chunks_per_owner",
        "offset_wire_bytes_per_owner", "wire_bytes_all_owners",
        "c03_records_all_owners",
    }, "owner-frames")
    need(owner["owner_count"] == 3 and
         owner["values_per_owner"] == 2635409 and
         owner["preprocessing_payload_bytes_per_owner"] == 421665440 and
         owner["preprocessing_chunks_per_owner"] == 6435 and
         owner["offset_payload_bytes_per_owner"] == 84333088 and
         owner["offset_chunks_per_owner"] == 1287 and
         owner["c03_records_all_owners"] == 3 * (6435 + 1287) and
         wire(owner["preprocessing_payload_bytes_per_owner"]) ==
         owner["preprocessing_wire_bytes_per_owner"] and
         wire(owner["offset_payload_bytes_per_owner"]) ==
         owner["offset_wire_bytes_per_owner"] and
         owner["wire_bytes_all_owners"] == owner["owner_count"] *
         (owner["preprocessing_wire_bytes_per_owner"] +
          owner["offset_wire_bytes_per_owner"]), "owner-frames")

    lanes = receipt["fixed_non_scalar_lanes"]
    exact_keys(lanes, {
        "terminal", "mac_and_group", "query_store_separate_payload_bytes",
        "query_binding",
    }, "fixed-lanes")
    exact_keys(lanes["terminal"], {"payloads", "wire_bytes"},
               "terminal-lanes")
    exact_keys(lanes["mac_and_group"], {"payloads", "wire_bytes"},
               "mac-group-lanes")
    need(lanes["terminal"]["payloads"] == [332, 10685, 32, 496, 0] and
         lanes["mac_and_group"]["payloads"] ==
         [32, 521, 781, 261, 261, 259, 259, 64, 130, 130, 129] and
         lanes["query_binding"] ==
         "HELLO preimage plus authenticated group-state stages" and
         sum(wire(value) for value in lanes["terminal"]["payloads"]) ==
         lanes["terminal"]["wire_bytes"] and
         sum(wire(value) for value in lanes["mac_and_group"]["payloads"]) ==
         lanes["mac_and_group"]["wire_bytes"] and
         lanes["query_store_separate_payload_bytes"] == 0, "fixed-lanes")

    openings = receipt["field_openings"]
    exact_keys(openings, {
        "hidden_payloads", "hidden_wire_bytes", "baseline_extra_payload",
        "baseline_extra_wire_bytes", "baseline_wire_bytes",
    }, "field-openings")
    need(openings["hidden_payloads"] == [32, 64, 331648] and
         openings["baseline_extra_payload"] == 25728 and
         sum(wire(value) for value in openings["hidden_payloads"]) ==
         openings["hidden_wire_bytes"] and
         wire(openings["baseline_extra_payload"]) ==
         openings["baseline_extra_wire_bytes"] and
         openings["baseline_wire_bytes"] == openings["hidden_wire_bytes"] +
         openings["baseline_extra_wire_bytes"], "field-openings")

    base_hidden = (fixed["wire_bytes"] + owner["wire_bytes_all_owners"] +
                   lanes["terminal"]["wire_bytes"] +
                   lanes["mac_and_group"]["wire_bytes"] +
                   openings["hidden_wire_bytes"])
    base_baseline = base_hidden + openings["baseline_extra_wire_bytes"]
    totals = receipt["symbolic_totals"]
    exact_keys(totals, {
        "H", "F", "T", "base_no_fork_hidden", "base_no_fork_baseline",
        "fd_round_hidden", "fd_round_baseline", "hidden_logical_messages",
        "hidden_c03_records", "baseline_additional_logical_messages",
        "baseline_additional_c03_records",
    }, "symbolic-totals")
    need(base_hidden == 19861945316 and base_baseline == 19861971156 and
         totals["base_no_fork_hidden"] == "19861945316 + 57408*H" and
         totals["base_no_fork_baseline"] == "19861971156 + 57408*H" and
         totals["fd_round_hidden"] ==
         "19861945316 + 57408*H + 208*F + sum(W(len(e.payload)) for e in T)" and
         totals["fd_round_baseline"] ==
         "19861971156 + 57408*H + 208*F + sum(W(len(e.payload)) for e in T)" and
         totals["hidden_logical_messages"] ==
         "11989984 + 72*H + F + len(T)" and
         totals["hidden_c03_records"] ==
         "12066151 + 72*H + F + sum(max(1,ceil(len(e.payload)/65536)) for e in T)" and
         totals["baseline_additional_logical_messages"] == 1 and
         totals["baseline_additional_c03_records"] == 1,
         "base-formula")

    need(receipt["missing_bound_reasons"] == MISSING_BOUND_REASONS and
         receipt["future_authority_minimum"] == FUTURE_AUTHORITY_MINIMUM,
         "boundary-ledger-cardinality")

    if check_sources:
        for relative, expected in pins["files"].items():
            path = REPO / relative
            need(path.is_file() and sha256_path(path) == expected,
                 "source-pin:" + relative)
        selection = json.loads((REPO / ".local/mpc-prover-softspoken-vendor/"
                                "SOURCE-SELECTION.json").read_text())
        need(selection["mp_spdz_commit"] == pins["mp_spdz_commit"],
             "mp-spdz-commit")

    if check_trace:
        container = REPO / (".local/private-batch-financial-trace-20261028-01/"
                            "artifact/trace.txt.gz")
        need(container.is_file() and sha256_path(container) ==
             pins["trace_container_sha256"], "trace-container")
        digest = hashlib.sha256()
        count = 0
        with gzip.open(container, "rb") as source:
            while block := source.read(1024 * 1024):
                digest.update(block)
                count += len(block)
        need(count == pins["trace_canonical_bytes"] and
             digest.hexdigest() == pins["trace_canonical_sha256"],
             "trace-canonical")


def load_receipt() -> dict:
    return json.loads(RECEIPT.read_text(encoding="utf-8"))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--skip-source-pins", action="store_true")
    parser.add_argument("--skip-trace", action="store_true")
    args = parser.parse_args()
    verify_receipt(load_receipt(),
                   check_sources=not args.skip_source_pins,
                   check_trace=not args.skip_trace)
    print("P1_V9_TYPED_SCHEDULE_VERIFIED_FD23_FD28_MISSING")


if __name__ == "__main__":
    main()
