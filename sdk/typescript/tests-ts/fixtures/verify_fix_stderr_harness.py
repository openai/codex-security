"""Run verify-fix fixture processes with broken or congested stderr and emit JSON results.

A separate pipe carries synchronization events so tests can observe worker completion,
cancellation, and cleanup even when the simulated terminal stops accepting output.
"""

from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import json
import os
from pathlib import Path
import pty
import select
import signal
import struct
import subprocess
import sys
import termios
import threading
import time


NODE, FIXTURE, CWD, STATE_ROOT, SCENARIO_TIMEOUT = sys.argv[1:]


class HarnessTermination(Exception):
    """Unwind a scenario on SIGTERM so the harness can clean up its process group."""

    pass


def terminate_harness(_signal_number, _frame):
    # Unwind the active scenario so its process-group cleanup always runs.
    raise HarnessTermination("output-isolation harness terminated")


signal.signal(signal.SIGTERM, terminate_harness)


def wait(process: subprocess.Popen, timeout: float = 10):
    """Return True if the child is still running after the timeout, in seconds."""
    try:
        process.wait(timeout=timeout)
        return False
    except subprocess.TimeoutExpired:
        return True


class RunningProcess:
    """Own a fixture subprocess, its process group, and the read end of its synchronization pipe.

    The process attribute is the Node child. The state path is where its worker
    publishes a PID. Use event_until to synchronize with that worker and finish
    to collect the exit status and output. The running context manager releases
    the process group and descriptors on exit.
    """

    def __init__(self, scenario: str, stderr, label: str):
        self.label = label
        sync_read, sync_write = os.pipe()
        environment = os.environ.copy()
        environment["VERIFY_FIX_SYNC_FD"] = str(sync_write)
        self.state = Path(STATE_ROOT, f"{scenario}.json")
        self.state.unlink(missing_ok=True)
        environment["VERIFY_FIX_WORKER_STATE"] = str(self.state)
        try:
            self.process = subprocess.Popen(
                [NODE, FIXTURE, scenario],
                cwd=CWD,
                env=environment,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=stderr,
                pass_fds=(sync_write,),
                start_new_session=True,
            )
        except BaseException:
            os.close(sync_read)
            os.close(sync_write)
            raise
        os.close(sync_write)
        self.process_group = self.process.pid
        if self.process_group == os.getpgrp():
            self.process.kill()
            self.process.wait()
            os.close(sync_read)
            raise AssertionError("fixture process group was not isolated")
        self.sync_fd = sync_read
        self.sync_buffer = b""

    def send(self, command: str = "continue"):
        """Write one newline-terminated command to the child and flush it immediately."""
        if self.process.stdin is None or self.process.stdin.closed:
            raise AssertionError("fixture stdin is closed")
        self.process.stdin.write(f"{command}\n".encode())
        self.process.stdin.flush()

    def _next_event(self, timeout: float = 10):
        """Decode one newline-delimited JSON event, retaining later events in the read buffer."""
        deadline = time.monotonic() + timeout
        while b"\n" not in self.sync_buffer:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise AssertionError("timed out waiting for fixture synchronization")
            readable, _, _ = select.select([self.sync_fd], [], [], remaining)
            if not readable:
                raise AssertionError("timed out waiting for fixture synchronization")
            chunk = os.read(self.sync_fd, 65_536)
            if not chunk:
                raise AssertionError("fixture synchronization closed unexpectedly")
            self.sync_buffer += chunk
        line, self.sync_buffer = self.sync_buffer.split(b"\n", 1)
        return json.loads(line)

    def event_until(self, name: str, worker: int | None = None):
        """Read synchronization events through the first matching milestone.

        Args:
            name (str): Event name emitted by the child.
            worker (int | None): Require a matching worker ID when supplied.

        Returns:
            list: All events read by this call, including the matching event.

        Raises:
            AssertionError: The synchronization pipe closes or times out before the milestone.
        """
        events = []
        while True:
            try:
                event = self._next_event()
            except (AssertionError, TimeoutError) as error:
                # Give an exiting fixture time to report its own status, then reap its group.
                wait(self.process, 1)
                self.stop()
                raise AssertionError(
                    f"{self.label}: {error} waiting for {name!r} (worker {worker}); "
                    f"exit {self.process.returncode}, events: {events}, stderr: {self.read_stderr()}"
                ) from error
            events.append(event)
            if event.get("event") == name and (
                worker is None or event.get("worker") == worker
            ):
                return events

    def close_stdin(self):
        if self.process.stdin is not None and not self.process.stdin.closed:
            self.process.stdin.close()

    def signal_group(self, sent_signal: signal.Signals):
        try:
            os.killpg(self.process_group, sent_signal)
        except ProcessLookupError:
            # The process group can already be gone when cleanup runs.
            pass

    def stop(self):
        """Stop the fixture, escalating to SIGKILL and cleaning up any descendants still in its group."""
        if self.process.poll() is None:
            self.signal_group(signal.SIGTERM)
            if wait(self.process, 1):
                self.signal_group(signal.SIGKILL)
                if wait(self.process, 2):
                    raise AssertionError("fixture process did not exit after SIGKILL")
        # Assertions inspect worker PIDs before leaving the running() context.
        # Afterwards, clean any abnormal descendant still in this isolated group.
        self.signal_group(signal.SIGKILL)

    def _remaining_events(self):
        chunks = [self.sync_buffer]
        self.sync_buffer = b""
        while True:
            chunk = os.read(self.sync_fd, 65_536)
            if not chunk:
                break
            chunks.append(chunk)
        return [json.loads(line) for line in b"".join(chunks).splitlines() if line]

    def read_stderr(self):
        stream = self.process.stderr
        if stream is None or stream.closed:
            return ""
        return stream.read().decode(errors="replace")

    def collect(self, events, blocked: bool = False):
        """Drain events into the supplied list and return exit status, captured output, and the blocked flag."""
        if self.process.poll() is None:
            self.process.wait()
        events.extend(self._remaining_events())
        stdout = (
            self.process.stdout.read().decode()
            if self.process.stdout is not None
            else ""
        )
        return {
            "exit": self.process.returncode,
            "blocked": blocked,
            "stdout": stdout,
            "stderr": self.read_stderr(),
            "events": events,
        }

    def finish(self, events, timeout: float = 10):
        """Close stdin, then wait for the child before collecting its final state.

        Args:
            events (list): Previously observed synchronization events, extended in place.
            timeout (float): Seconds to wait for normal exit before stopping the group.

        Returns:
            dict: Exit code, timeout flag (blocked), stdout, stderr, and all observed events.
        """
        self.close_stdin()
        blocked = wait(self.process, timeout)
        if blocked:
            self.stop()
        return self.collect(events, blocked)

    def cleanup(self):
        self.stop()
        self.close_stdin()
        for stream in (self.process.stdout, self.process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
        try:
            os.close(self.sync_fd)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


@contextmanager
def running(scenario: str, stderr=subprocess.PIPE, *, label: str | None = None):
    """Yield an isolated fixture process and clean it up on completion, interruption, or timeout."""

    def timeout(_signal_number, _frame):
        raise TimeoutError(f"Verification fixture timed out: {scenario}")

    fixture = RunningProcess(scenario, stderr, label or scenario)
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(int(SCENARIO_TIMEOUT))
    try:
        yield fixture
    finally:
        signal.alarm(0)
        fixture.cleanup()


def read_pty(master: int):
    """Read the master end through EOF or terminal hangup and decode the captured output."""
    chunks = []
    while True:
        try:
            chunk = os.read(master, 65_536)
        except OSError as error:
            if error.errno == errno.EIO:
                break
            raise
        if not chunk:
            break
        chunks.append(chunk)
    return b"".join(chunks).decode(errors="replace")


def drain_pty(master: int, stopped: threading.Event):
    while not stopped.is_set():
        readable, _, _ = select.select([master], [], [], 0.05)
        if not readable:
            continue
        try:
            if not os.read(master, 65_536):
                return
        except OSError as error:
            if error.errno in {errno.EBADF, errno.EIO}:
                return
            raise


def open_pty():
    """Return master and slave descriptors for a terminal with 24 rows and 100 columns."""
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
    return master, slave


def wait_for_worker(state: Path):
    """Return the PID written by a worker, raising AssertionError if its state file fails to appear."""
    deadline = time.monotonic() + 10
    while not state.exists():
        if time.monotonic() >= deadline:
            raise AssertionError("worker did not publish its PID")
        time.sleep(0.01)
    return json.loads(state.read_text())["pid"]


def process_exists(pid: int):
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def disconnected_pipe(scenario: str):
    name = f"pipe-{scenario}"
    with running(scenario, label=name) as fixture:
        events = fixture.event_until("worker-started", 2)
        fixture.process.stderr.close()
        fixture.send()
        return {"scenario": name, **fixture.finish(events)}


def connected_output(scenario: str, name: str, stderr=subprocess.PIPE):
    with running(scenario, stderr, label=name) as fixture:
        events = fixture.event_until("worker-started", 2)
        fixture.send()
        return {"scenario": name, **fixture.finish(events)}


def fill_output(fd: int):
    """Fill the descriptor until a single byte would block, then restore blocking mode."""
    os.set_blocking(fd, False)
    try:
        chunk = b"x" * 4096
        while True:
            try:
                os.write(fd, chunk)
            except BlockingIOError:
                if len(chunk) == 1:
                    # Even a one-byte write would block.
                    return
                chunk = b"x"
    finally:
        os.set_blocking(fd, True)


def full_pipe():
    reader, writer = os.pipe()
    try:
        fill_output(writer)
        return connected_output("worker-failure", "full-pipe", writer)
    finally:
        os.close(reader)
        os.close(writer)


def disconnected_pty(scenario: str):
    master, slave = open_pty()
    try:
        with running(scenario, slave) as fixture:
            os.close(slave)
            slave = -1
            if scenario == "pty-oversized":
                events = fixture.event_until("selecting")
            else:
                events = fixture.event_until("worker-started", 2)
            os.close(master)
            master = -1
            os.kill(fixture.process.pid, signal.SIGWINCH)
            if scenario == "pty-oversized":
                events.extend(fixture.event_until("selection-resized"))
            fixture.send()
            return {"scenario": scenario, **fixture.finish(events)}
    finally:
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)


def release_with_full_terminal(fixture: RunningProcess, slave: int):
    """Fill terminal output before releasing the second worker and return its startup events."""
    events = fixture.event_until("worker-started", 2)
    # Use a separate file description so the fixture's stderr stays blocking.
    with open(os.ttyname(slave), "wb", buffering=0) as filler:
        fill_output(filler.fileno())
    fixture.send()
    return events


def paused_pty(scenario: str, sent_signal: signal.Signals | None):
    """Return completion and worker-liveness observations while leaving terminal output undrained."""
    master, slave = open_pty()
    try:
        with running(scenario, slave) as fixture:
            events = release_with_full_terminal(fixture, slave)
            os.close(slave)
            slave = -1
            events.extend(fixture.event_until("progress-queued"))
            worker_pid = None
            if sent_signal is not None:
                worker_pid = wait_for_worker(fixture.state)
                os.kill(fixture.process.pid, sent_signal)
            events.extend(fixture.event_until("complete"))
            fixture.close_stdin()
            blocked = wait(fixture.process, 2)
            if blocked:
                os.close(master)
                master = -1
                fixture.stop()
            result = fixture.collect(events, blocked)
            return {
                "scenario": scenario,
                **result,
                "drained": 0,
                "workerPid": worker_pid,
                "workerAlive": worker_pid is not None
                and process_exists(worker_pid),
            }
    finally:
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)


def full_terminal(scenario: str):
    master, slave = open_pty()
    try:
        with running(scenario, slave) as fixture:
            events = release_with_full_terminal(fixture, slave)
            os.close(slave)
            slave = -1
            if scenario == "pty-text-update":
                result = fixture.finish(events)
                # Inspect the terminal only after verification has exited.
                result["stderr"] = read_pty(master)
                return {"scenario": scenario, **result}
            events.extend(fixture.event_until("progress-queued"))
            worker_pid = wait_for_worker(fixture.state)
            return {
                "scenario": scenario,
                **fixture.finish(events),
                "workerPid": worker_pid,
                "workerAlive": process_exists(worker_pid),
            }
    finally:
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)


def mixed_signals(first: signal.Signals, second: signal.Signals):
    """Send the second signal after the worker observes the first and collect the final worker state."""
    scenario = f"pty-backpressure-mixed-{first.name.lower()}-{second.name.lower()}"
    master, slave = open_pty()
    try:
        with running(scenario, slave) as fixture:
            events = release_with_full_terminal(fixture, slave)
            os.close(slave)
            slave = -1
            events.extend(fixture.event_until("progress-queued"))
            worker_pid = wait_for_worker(fixture.state)
            os.kill(fixture.process.pid, first)
            events.extend(fixture.event_until("worker-signaled"))
            os.kill(fixture.process.pid, second)
            events.extend(fixture.event_until("complete"))
            fixture.close_stdin()
            blocked = wait(fixture.process, 3)
            if blocked:
                os.close(master)
                master = -1
                fixture.stop()
            result = fixture.collect(events, blocked)
            return {
                "scenario": scenario,
                **result,
                "workerPid": worker_pid,
                "workerAlive": process_exists(worker_pid),
                "firstSignal": first.name,
                "secondSignal": second.name,
            }
    finally:
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)


def cleanup_sigwinch():
    """Deliver a resize signal after terminal cleanup and capture the fixture's response."""
    master, slave = open_pty()
    stop_reader = threading.Event()
    reader = threading.Thread(target=drain_pty, args=(master, stop_reader))
    reader.start()
    try:
        with running("pty-cleanup-sigwinch", slave) as fixture:
            os.close(slave)
            slave = -1
            events = fixture.event_until("worker-started", 2)
            fixture.send()
            events.extend(fixture.event_until("invocation-complete"))
            events.extend(fixture.event_until("invocation-complete"))
            events.extend(fixture.event_until("worker-started", 2))
            fixture.send()
            events.extend(fixture.event_until("cleanup-ready"))
            stop_reader.set()
            reader.join(timeout=2)
            if reader.is_alive():
                raise AssertionError("PTY reader did not stop")
            os.close(master)
            master = -1
            os.kill(fixture.process.pid, signal.SIGWINCH)
            events.extend(fixture.event_until("post-cleanup-sigwinch"))
            fixture.send("finish")
            return {
                "scenario": "pty-cleanup-sigwinch",
                **fixture.finish(events),
            }
    finally:
        stop_reader.set()
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)
        reader.join(timeout=2)


def simple_process(scenario: str):
    with running(scenario) as fixture:
        return {"scenario": scenario, **fixture.finish([])}


def simple_pty_process(scenario: str):
    master, slave = open_pty()
    stderr = []
    reader = threading.Thread(target=lambda: stderr.append(read_pty(master)))
    reader.start()
    try:
        with running(scenario, slave) as fixture:
            os.close(slave)
            slave = -1
            events = fixture.event_until("complete")
            result = fixture.finish(events)
            reader.join(timeout=2)
            if reader.is_alive():
                raise AssertionError("PTY reader did not finish")
            result["stderr"] = "".join(stderr)
            return {"scenario": scenario, **result}
    finally:
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)
        reader.join(timeout=2)


results = [
    disconnected_pipe("quiet-success"),
    disconnected_pipe("progress-success"),
    disconnected_pipe("worker-failure"),
    connected_output("unrelated-stderr-error", "pipe-unrelated-stderr-error"),
    full_pipe(),
    disconnected_pty("pty-quiet-success"),
    disconnected_pty("pty-oversized"),
    paused_pty("pty-backpressure-success", None),
    paused_pty("pty-backpressure-sigint", signal.SIGINT),
    paused_pty("pty-backpressure-sigterm", signal.SIGTERM),
    full_terminal("pty-backpressure-worker-failure"),
    full_terminal("pty-text-update"),
    mixed_signals(signal.SIGINT, signal.SIGTERM),
    mixed_signals(signal.SIGTERM, signal.SIGINT),
    cleanup_sigwinch(),
    simple_pty_process("single-saved-progress-interactive"),
    simple_process("single-saved-progress-ci"),
    simple_process("repeated-main"),
]
if Path("/dev/full").exists():
    with open("/dev/full", "wb", buffering=0) as full_device:
        results.append(connected_output("worker-failure", "full-device", full_device))
print(json.dumps(results))
