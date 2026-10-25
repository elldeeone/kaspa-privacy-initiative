"""Allowlisted neutral publication view of the SOURCE04 accounting result.

The caller authenticates SOURCE04 and its detailed result locally. This module
does no I/O. In particular, it never exports detailed input selections, scan
receipt hashes, participant identifiers, owner counts or owner-to-exit links.
Unknown detailed fields are ignored rather than copied into the public result.
"""
import re


AUDITOR_SHA256 = "c9c7b593bc12690e105158f01a9bd39fd99d0a029fca2883f70a69a6a1d47aa7"
MAX_SOMPI = 2_870_000_000_000_000_000
INTEGER_FIELDS = (
    "accepted_pool_transaction_count", "ordinary_acquisition_transaction_count",
    "accepted_payment_round_count", "confirmed_payout_count", "mined_source_sompi",
    "ordinary_GN3_change_sompi", "native_payout_sompi", "remaining_reserve_sompi",
    "acquisition_fees_sompi", "GN3_fee_sompi", "mixed_batch_total_fee_sompi",
    "independent_exit_total_fee_sompi", "pool_fees_sompi", "complete_fee_sompi_so_far",
    "fixed_useful_payment_sompi", "fee_ratio_numerator", "fee_ratio_denominator",
)
BOOLEAN_FIELDS = (
    "complete_requested_lifecycle", "financial_chain_terminal", "three_original_seed_terminal_scans",
    "whole_trial_sompi_conservation", "denominator_is_frozen_workload_not_decrypted_by_auditor",
    "independent_consensus_or_crypto_proof_verified", "privacy_or_separate_administration_qualified",
)
PUBLIC_PREFIX_PINS = ("fetch", "replay", "history", "checkpoint", "native-tail")


def neutral(detailed, *, auditor_sha256):
    if auditor_sha256 != AUDITOR_SHA256 or detailed["schema"] != "kpx8-independent-recorded-live-accounting/v1":
        raise ValueError("selected-auditor-result-required")
    report = {"schema": "kpx8-neutral-recorded-live-accounting/v1",
              "auditor_sha256": AUDITOR_SHA256,
              "scope": "RECORDED_SELECTED_NODE_PREFIX_ARITHMETIC_AND_RECEIPT_JOINS"}
    for name in INTEGER_FIELDS:
        value = detailed[name]
        if type(value) is not int or not 0 <= value <= MAX_SOMPI:
            raise ValueError("public-integer-field")
        report[name] = value
    for name in BOOLEAN_FIELDS:
        value = detailed[name]
        if type(value) is not bool:
            raise ValueError("public-boolean-field")
        report[name] = value
    verdict = detailed["two_percent_target_verdict"]
    if verdict not in ("PASS", "FAIL", "INCOMPLETE"):
        raise ValueError("public-fee-verdict")
    report["two_percent_target_verdict"] = verdict
    public_pins = {}
    for name in PUBLIC_PREFIX_PINS:
        value = detailed["input_sha256"][name]
        if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
            raise ValueError("public-prefix-pin")
        public_pins[name] = value
    report["accepted_prefix_evidence_sha256"] = public_pins
    # These booleans report the selected local checks without exporting their
    # cohort or receipt selection. They are not independent ownership proofs.
    report["terminal_scan_cohort_equality_checked_locally"] = detailed["three_original_seed_terminal_scans"]
    report["terminal_claims_and_payout_keys_reconciled_locally"] = detailed["three_original_seed_terminal_scans"]
    return report
