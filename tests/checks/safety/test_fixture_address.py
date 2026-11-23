"""The payload address must be the canary's private-network interface."""

from types import SimpleNamespace

import pytest

from probe.config.profile import FixturesSection
from probe.sandbox.fixtures import FixtureSet


def test_canary_ip_uses_the_private_interface() -> None:
    canary = SimpleNamespace(
        attrs={
            "NetworkSettings": {
                "Networks": {
                    "probe-priv-test": {"IPAddress": "172.20.4.2"},
                    "probe-ctl-test": {"IPAddress": "172.30.1.9"},
                }
            }
        }
    )
    sandbox = SimpleNamespace(names={"priv": "probe-priv-test"})
    fixtures = FixtureSet(sandbox, FixturesSection(), token="a1b2c3d4e5f6")
    fixtures._canary = canary
    assert fixtures.canary_ip == "172.20.4.2"


def test_canary_ip_is_unavailable_until_started() -> None:
    fixtures = FixtureSet(SimpleNamespace(), FixturesSection(), token="a1b2c3d4e5f6")
    with pytest.raises(RuntimeError, match=r"canary.*started"):
        _ = fixtures.canary_ip
