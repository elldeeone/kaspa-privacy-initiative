#!/usr/bin/env python3
"""Public, source-only terminal Exit-privacy acceptance boundary.

This module never receives private truth or raw observer bundles. It binds the
two private bundle seals in the count-only score, but deliberately cannot
authorize a rehearsal until a separate isolated actual-capture/score receipt
exists.
"""
import terminal_exit_privacy as model


ACTUAL_AUTHORITY_IMPLEMENTED = False


def evaluate(selection_sha256, baseline_bundle_sha256,
             candidate_bundle_sha256, private_score):
    model.word(selection_sha256, 'acceptance-selection-sha256')
    result = model.source_only_acceptance(
        selection_sha256, baseline_bundle_sha256,
        candidate_bundle_sha256, private_score)
    model.need(ACTUAL_AUTHORITY_IMPLEMENTED is False
         and result['actual_capture_and_private_score_executed'] is False
         and result['rehearsal_authorized'] is False,
         'source-only-cannot-authorize')
    return result
