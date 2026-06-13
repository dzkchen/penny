from __future__ import annotations

from penny.feed import EventFeed
from penny.replay import run_demo_replay

from .conftest import PAYMENT_SECRET, SERVICE_KEY


def test_demo_replay_writes_redacted_known_good_session(tmp_path) -> None:
    findings_path, report_path = run_demo_replay(out_dir=tmp_path, feed=EventFeed(quiet=True))

    assert findings_path.exists()
    assert report_path.exists()
    combined = findings_path.read_text(encoding="utf-8") + report_path.read_text(encoding="utf-8")
    assert "critical client-exposed service credential confirmed" in combined.lower()
    assert SERVICE_KEY not in combined
    assert PAYMENT_SECRET not in combined
