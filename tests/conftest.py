from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import pytest

ROOT = Path(__file__).resolve().parents[1]
SERVICE_KEY = "sb_service_role_PENNY_DEMO_SUPER_PRIVATE_DO_NOT_SHIP_2026"
PAYMENT_SECRET = "sk_live_penny_demo_51NnDemoSecretValueThatShouldNotShip"


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def planted_server():
    port = find_free_port()
    env = os.environ.copy()
    env["PORT"] = str(port)
    process = subprocess.Popen(
        [sys.executable, str(ROOT / "planted-app/server/app.py")],
        cwd=str(ROOT),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    url = f"http://127.0.0.1:{port}"
    deadline = time.time() + 5
    while time.time() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=1)
            raise RuntimeError(f"planted app exited early\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")
        try:
            with urlopen(f"{url}/health", timeout=0.2) as response:
                if response.status == 200:
                    break
        except URLError:
            time.sleep(0.05)
    else:
        process.terminate()
        raise RuntimeError("planted app did not become healthy")

    try:
        yield url
    finally:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
