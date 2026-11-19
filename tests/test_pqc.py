"""Unit tests: post-quantum channel, enforcer, pipeline.  Run:  pytest tests -q"""
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from attack_detective.enforcer.enforcer import Enforcer
from attack_detective.pqc.backend import PQCUnavailable, load_pq
from attack_detective.pqc.channel import make_pair
from attack_detective.pqc.primitives import canonical, pack, unpack
from attack_detective.pqc.replay import ReplayGuard
from attack_detective.pipeline.run_pipeline import run

DEC = {"flow_id": 7, "score": 3.2, "action": "BLOCK", "reason": "test",
       "techniques": [{"technique_id": "T1046", "name": "Network Service Discovery", "similarity": 0.4}]}


def test_canonical_json_is_stable():
    assert canonical({"b": 1, "a": [1, 2]}) == canonical({"a": [1, 2], "b": 1}) == b'{"a":[1,2],"b":1}'


def test_pack_roundtrip_and_truncation():
    parts = [b"a", b"", b"xyz" * 100]
    assert unpack(pack(parts)) == parts
    with pytest.raises(ValueError):
        unpack(pack(parts)[:-1])


def test_replay_guard():
    g, now = ReplayGuard(30), time.time()
    assert g.check("s", 1, now, now) is None
    assert g.check("s", 1, now, now) == "replay"
    assert g.check("s", 2, now - 100, now) == "stale_timestamp"


@pytest.mark.parametrize("mode", ["classical", "hybrid", "pq"])
def test_roundtrip_and_tamper(mode):
    s, r = make_pair(mode, allow_pure=True)
    assert r.accept_handshake(s.handshake()) == (True, "ok")
    blob = s.seal(DEC)
    ok, why, alert = r.receive(blob)
    assert ok and alert["decision"]["flow_id"] == 7
    assert r.receive(blob)[1] == "replay"
    bad = bytearray(s.seal(DEC)); bad[-5] ^= 1
    assert r.receive(bytes(bad))[1] == "decrypt_failed"
    assert r.receive(s.seal(DEC, sign=False))[1] == "unsigned"


def test_fail_closed_when_backend_missing():
    with pytest.raises(PQCUnavailable):
        load_pq("does-not-exist")


def test_enforcer_applies_only_verified_alerts(tmp_path):
    s, r = make_pair("hybrid", allow_pure=True)
    e = Enforcer(r, log_path=tmp_path / "log.jsonl")
    assert e.on_handshake(s.handshake())
    assert e.on_alert(s.seal(DEC))[0]
    assert e.firewall.rules == {7: "BLOCK"}
    assert not e.on_alert(s.seal({**DEC, "flow_id": 8}, sign=False))[0]
    assert 8 not in e.firewall.rules
    e.save_log()
    assert (tmp_path / "log.jsonl").read_text(encoding="utf-8").count("\n") == 3


def test_pipeline_end_to_end():
    out = run([DEC, {**DEC, "flow_id": 9, "action": "ALLOW"}], "pq", allow_pure=True)
    assert out["accepted"] == 2 and out["firewall"]["BLOCK"] == 1
