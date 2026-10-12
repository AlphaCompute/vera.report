#!/usr/bin/env python3
"""Verify an ordered audit history against independently supplied endpoints."""
import argparse
import hashlib
import json
import re
import sys

MAX_BYTES = 1024 * 1024
MAX_ANCHORS = 1000
DIGEST = re.compile(r"[a-f0-9]{64}\Z")


def is_digest(value):
    return isinstance(value, str) and DIGEST.fullmatch(value) is not None


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def verify(anchors, head, checkpoint):
    if not is_digest(head) or (checkpoint is not None and not is_digest(checkpoint)):
        return "invalid_endpoint"
    if not isinstance(anchors, list) or len(anchors) > MAX_ANCHORS:
        return "invalid_history_length"
    expected = head
    seen = set()
    for anchor in anchors:
        if expected == checkpoint:
            return "extra_anchors"
        if not isinstance(anchor, dict) or anchor.get("root") != expected or expected in seen:
            return "broken_link"
        seen.add(expected)
        version = anchor.get("commitmentVersion")
        if version is None:
            return "legacy_boundary"
        if type(version) is not int or version != 2:
            return "unsupported_version"
        batch = anchor.get("batchRoot")
        count = anchor.get("eventCount")
        previous = anchor.get("prevRoot")
        if not is_digest(batch) or type(count) is not int or not 1 <= count <= 2048:
            return "invalid_commitment"
        if previous is not None and not is_digest(previous):
            return "invalid_predecessor"
        encoded = json.dumps(["vera:audit:history:v2", batch, count, previous], separators=(",", ":")).encode("utf-8")
        if hashlib.sha256(encoded).hexdigest() != expected:
            return "commitment_mismatch"
        expected = previous
    return None if expected == checkpoint else "missing_anchors"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--head", required=True, help="Independently trusted newest committed root")
    parser.add_argument("--tail", required=True, help="Trusted older root, or genesis; this endpoint is excluded from the input path")
    args = parser.parse_args()
    try:
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            raise ValueError("oversized input")
        data = json.loads(raw, object_pairs_hook=unique_object)
        anchors = data.get("anchors") if isinstance(data, dict) else None
        checkpoint = None if args.tail == "genesis" else args.tail
        reason = verify(anchors, args.head, checkpoint)
        result = {"consistent": reason is None, "trust": "caller-supplied endpoints"}
        if reason:
            result["reason"] = reason
        else:
            result.update({"anchorCount": len(anchors), "head": args.head, "checkpoint": checkpoint})
    except (ValueError, TypeError, RecursionError, UnicodeError):
        result = {"consistent": False, "reason": "invalid_input", "trust": "caller-supplied endpoints"}
    print(json.dumps(result, separators=(",", ":")))
    return 0 if result["consistent"] else 1


if __name__ == "__main__":
    sys.exit(main())
