from __future__ import annotations

import subprocess
import sys

from .conftest import ROOT


def test_cli_run_rejects_website_url_as_scan_path(tmp_path) -> None:
    stale_report = tmp_path / "report.md"
    stale_report.write_text("stale report\n", encoding="utf-8")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "penny",
            "run",
            "https://example.com",
            "--target",
            "https://example.com",
            "--out",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert result.returncode == 2
    assert "Do not pass a deployed website URL" in result.stderr
    assert stale_report.read_text(encoding="utf-8") == "stale report\n"
