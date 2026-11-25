"""The target is hostile; no caller input can weaken the sandbox contract."""

import pytest

from probe.sandbox.spec import names, target_spec, validate_scan_id


@pytest.mark.parametrize("scan", ["", "../x", "UPPER", "a/b", "-x", "x-", "a" * 49, "x\n"])
def test_unsafe_scan_ids_are_rejected(scan):
    with pytest.raises(ValueError):
        validate_scan_id(scan)


def test_names_labels_and_all_hardening_flags():
    assert names("abc") == {
        "pub": "probe-pub-abc",
        "priv": "probe-priv-abc",
        "ctl": "probe-ctl-abc",
        "data": "probe-data-abc",
    }
    spec = target_spec("abc", "image:tag", command=["python", "-m", "server"], created=123)
    assert spec["labels"] == {"probe.scan": "abc", "probe.created": "123"}
    assert spec["user"] == "10001:10001"
    assert spec["read_only"] is True
    assert spec["tmpfs"] == {  # private container tmpfs
        "/tmp": "rw,size=64m,mode=1777",  # noqa: S108
        "/home/probe": "rw,size=64m",
    }
    assert spec["environment"] == {
        "HOME": "/home/probe",
        "TZ": "UTC",
        "LANG": "C.UTF-8",
        "PYTHONUNBUFFERED": "1",
        "PYTHONIOENCODING": "utf-8",
    }
    assert spec["cap_drop"] == ["ALL"]
    assert spec["security_opt"] == ["no-new-privileges"]
    assert spec["pids_limit"] == 256
    assert spec["mem_limit"] == spec["memswap_limit"] == "1g"
    assert spec["nano_cpus"] == 1_000_000_000
    assert spec["ulimits"] == [{"Name": "nofile", "Soft": 1024, "Hard": 1024}]
    assert spec["init"] is True
    assert spec["network"] == "probe-pub-abc"
    assert spec["volumes"] == {"probe-data-abc": {"bind": "/data", "mode": "rw"}}
    assert spec["stdin_open"] is True and spec["tty"] is False
    assert spec["entrypoint"] == ["python"]
    assert spec["command"] == ["-m", "server"]
    assert "ports" not in spec and "privileged" not in spec
    assert "runtime" not in spec


def test_default_image_command_and_optional_runsc():
    spec = target_spec("x", "img", runtime="runsc")
    assert "entrypoint" not in spec and "command" not in spec
    assert spec["runtime"] == "runsc"
    assert target_spec("x", "img", command=["executable"])["command"] == []


@pytest.mark.parametrize(
    "kwargs",
    [
        {"runtime": "runc"},
        {"command": []},
        {"command": ["bad\0"]},
        {"env": {"BAD=KEY": "x"}},
        {"env": {"X": "a\0b"}},
        {"env": {"HOME": "/host"}},
    ],
)
def test_invalid_or_weakening_configuration_is_rejected(kwargs):
    with pytest.raises(ValueError):
        target_spec("x", "img", **kwargs)


def test_command_string_is_not_an_argv():
    with pytest.raises(ValueError, match="argv"):
        target_spec("x", "image", command="python")


def test_docker_user_proxy_configuration_is_not_injected():
    assert target_spec("x", "image")["use_config_proxy"] is False


def test_target_logs_have_bounded_rotation():
    spec = target_spec("disk", "image")
    assert spec["log_config"] == {
        "Type": "json-file",
        "Config": {"max-size": "10m", "max-file": "3"},
    }
