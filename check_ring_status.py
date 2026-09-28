#!/usr/bin/env python3
"""
Self-check for the live ring state (run directly: python3 check_ring_status.py).

Fixtures are getOperationResult.do responses captured on 2026-09-24 while ringing
and stopping the S22 Ultra and Buds3 Pro. parse_ring_op is loaded straight from
utils.py (without importing Home Assistant), so this tests the real code.
"""
import ast
import pathlib

src = pathlib.Path(__file__).with_name("custom_components") / "smartthings_find" / "utils.py"
tree = ast.parse(src.read_text())
wanted = [n for n in tree.body if
          (isinstance(n, ast.FunctionDef) and n.name == "parse_ring_op") or
          (isinstance(n, ast.Assign) and getattr(n.targets[0], "id", "") == "RING_ERRORS")]
ns = {}
exec(compile(ast.Module(body=wanted, type_ignores=[]), str(src), "exec"), ns)
parse = ns["parse_ring_op"]

queued = {"oprnStsCd": "1000", "oprnResultCode": "200", "oprnType": "RING"}
phone_ringing = {"oprnStsCd": "2800", "oprnResultCode": "1200",
                 "extra": {"battery": "85", "isConnected": True, "status": "4"}}
phone_idle = {"oprnStsCd": "2800", "oprnResultCode": "1200",
              "extra": {"battery": "85", "isConnected": True, "status": "0"}}
buds_ringing = {"oprnStsCd": "2800", "oprnResultCode": "1200",
                "extra": {"battery": "-1", "left": {"status": "4"}, "right": {"status": "4"}}}
buds_one_side = {"oprnStsCd": "2800", "oprnResultCode": "1200",
                 "extra": {"left": {"status": "5"}, "right": {"status": "2"}}}
buds_idle = {"oprnStsCd": "2800", "oprnResultCode": "1200",
             "extra": {"battery": "-1", "left": {"status": "2"}, "right": {"status": "2"}}}

assert parse(queued) == "pending"
assert parse(phone_ringing) == "ringing"
assert parse(phone_idle) == "idle"
assert parse(buds_ringing) == "ringing"
assert parse(buds_one_side) == "ringing"
assert parse(buds_idle) == "idle"
assert parse(None) == "unknown"  # tags: "operation": []
assert parse({"oprnStsCd": "2900", "oprnResultCode": "1452"}) == "error_fmm_off"
assert parse({"oprnStsCd": "2900", "oprnResultCode": "507"}) == "error_on_call"
assert parse({"oprnStsCd": "2900", "oprnResultCode": "3009"}) == "error_wearing"
assert parse({"oprnStsCd": "1900", "oprnResultCode": "99"}) == "error_99"
print("ring status: OK")
