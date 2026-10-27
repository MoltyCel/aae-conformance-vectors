"""Conformance runner for the AAE vectors.

Runs an implementation under test against the native and enforce vectors through the
adapter protocol in docs/RUNNER-PROTOCOL.md. Standard library only.
"""

RUNNER_VERSION = "1.1.0"
PROTOCOL = "aae-conformance-runner/1"

__all__ = ["RUNNER_VERSION", "PROTOCOL"]
