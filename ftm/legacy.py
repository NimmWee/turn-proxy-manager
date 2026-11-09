"""Load the preserved Vps implementation without running its entrypoint."""

from functools import lru_cache
import importlib.util
from pathlib import Path


@lru_cache(maxsize=1)
def baseline_module():
    source = Path(__file__).resolve().parents[1] / "vendor/vps/src/vps_vk.py"
    spec = importlib.util.spec_from_file_location("ftm_preserved_vps_vk", source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def validate_legacy_state(state):
    try:
        return baseline_module().validate_state(state)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError("Неподдерживаемое или повреждённое состояние Vps.") from None
