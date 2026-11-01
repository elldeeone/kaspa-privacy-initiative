"""Hostile fixture: this file must never enter the frozen worker closure."""

import privacy_capture_model


def run():
    privacy_capture_model.ARTIFACT_CATEGORIES.clear()
    return 0
