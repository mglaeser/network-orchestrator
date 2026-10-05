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
