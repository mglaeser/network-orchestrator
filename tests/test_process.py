import os
import sys
import time

import pytest

from netorch.process import OutputLimit, ProcessTimeout, run


def test_bounded_input_and_result():
    result = run(
        [sys.executable, "-c", "import sys; sys.stdout.buffer.write(sys.stdin.buffer.read())"],
        input_data=b"test",
    )
    assert result.returncode == 0
    assert result.stdout == b"test"


def test_output_is_bounded():
    with pytest.raises(OutputLimit):
        run([sys.executable, "-c", "print('x'*200000)"], max_output=1000)


def test_child_exit_does_not_hide_descendant_pipe_timeout():
    start = time.monotonic()
    script = "import os,time; pid=os.fork(); time.sleep(10) if pid==0 else None"
    with pytest.raises(ProcessTimeout):
        run([sys.executable, "-c", script], timeout=0.3)
    assert time.monotonic() - start < 3


def test_command_deadline_and_no_shell():
    with pytest.raises(ProcessTimeout):
        run([sys.executable, "-c", "import time; time.sleep(10)"], timeout=0.1)
    with pytest.raises(ValueError):
        run(["relative-command"])
    assert (
        run(
            [sys.executable, "-c", "import sys; print(sys.argv[1])", "$(false); `false`"]
        ).stdout.strip()
        == b"$(false); `false`"
    )


@pytest.mark.parametrize(
    "kwargs",
    [
        {"run_uid": 0, "run_gid": 0},
        {"run_uid": True, "run_gid": 1},
        {"run_uid": -1, "run_gid": 1},
        {"run_uid": 1},
        {"run_gid": 1},
        {"run_uid": 1, "run_gid": -1},
        {"account_home": "relative"},
        {"account_home": 42},
        {"account_home": "/private\0bad"},
    ],
)
def test_drop_credentials_are_strict(kwargs):
    with pytest.raises(ValueError):
        run([sys.executable, "-c", "pass"], **kwargs)


def test_dropped_account_minimal_environment(monkeypatch, tmp_path):
    monkeypatch.setenv("PRIVATE_TOKEN_FOR_TEST", "never-propagate")
    result = run(
        [
            sys.executable,
            "-c",
            "import os;print(os.environ.get('PRIVATE_TOKEN_FOR_TEST'));print(os.environ['HOME'])",
        ],
        run_uid=os.geteuid(),
        run_gid=os.getegid(),
        account_home=str(tmp_path),
    )
    assert result.stdout.decode().splitlines() == ["None", str(tmp_path)]


def test_user_cannot_select_another_account():
    if os.geteuid() == 0:
        pytest.skip("unprivileged account boundary test")
    with pytest.raises(PermissionError):
        run([sys.executable, "-c", "pass"], run_uid=os.geteuid() + 1, run_gid=os.getegid())


def test_root_drop_clears_supplementary_groups(monkeypatch):
    import subprocess

    original = subprocess.Popen
    captured = {}

    def spawn(argv, **kwargs):
        captured.update(kwargs)
        for key in ("user", "group", "extra_groups"):
            kwargs.pop(key, None)
        return original(argv, **kwargs)

    monkeypatch.setattr(os, "geteuid", lambda: 0)
    monkeypatch.setattr(subprocess, "Popen", spawn)
    result = run([sys.executable, "-c", "pass"], run_uid=123, run_gid=45)
    assert result.returncode == 0
    assert captured["user"] == 123 and captured["group"] == 45
    assert captured["extra_groups"] == []
