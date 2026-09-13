import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "python"))


@pytest.fixture(scope="session")
def fx():
    return json.loads((ROOT / "tests" / "fixtures.json").read_text())


@pytest.fixture(scope="session")
def now(fx):
    return fx["now"]


@pytest.fixture(scope="session")
def ids(fx):
    return fx["ids"]
