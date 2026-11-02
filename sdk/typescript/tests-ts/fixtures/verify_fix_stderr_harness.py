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
    pass


def terminate_harness(_signal_number, _frame):
    # Unwind the active scenario so its process-group cleanup always runs.
    raise HarnessTermination("output-isolation harness terminated")


signal.signal(signal.SIGTERM, terminate_harness)


def wait(process: subprocess.Popen, timeout: float = 10):
    try:
        process.wait(timeout=timeout)
        return False
    except subprocess.TimeoutExpired:
        return True


class RunningProcess:
    def __init__(self, scenario: str, stderr: int | None = subprocess.PIPE):
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
        if self.process.stdin is None or self.process.stdin.closed:
            raise AssertionError("fixture stdin is closed")
        self.process.stdin.write(f"{command}\n".encode())
        self.process.stdin.flush()

    def _next_event(self, timeout: float = 10):
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
        events = []
        while True:
            event = self._next_event()
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
            pass

    def stop(self):
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

    def collect(self, events, blocked: bool = False):
        if self.process.poll() is None:
            self.process.wait()
        events.extend(self._remaining_events())
        stdout = (
            self.process.stdout.read().decode()
            if self.process.stdout is not None
            else ""
        )
        stderr = (
            self.process.stderr.read().decode()
            if self.process.stderr is not None and not self.process.stderr.closed
            else ""
        )
        return {
            "exit": self.process.returncode,
            "blocked": blocked,
            "stdout": stdout,
            "stderr": stderr,
            "events": events,
        }

    def finish(self, events, timeout: float = 10):
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
        except OSError:
            pass


@contextmanager
def running(scenario: str, stderr: int | None = subprocess.PIPE):
    def timeout(_signal_number, _frame):
        raise TimeoutError(f"Verification fixture timed out: {scenario}")

    fixture = RunningProcess(scenario, stderr)
    signal.signal(signal.SIGALRM, timeout)
    signal.alarm(int(SCENARIO_TIMEOUT))
    try:
        yield fixture
    finally:
        signal.alarm(0)
        fixture.cleanup()


def read_pty(master: int):
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
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 100, 0, 0))
    return master, slave


def wait_for_worker(state: Path):
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
    with running(scenario) as fixture:
        events = fixture.event_until("worker-started", 2)
        fixture.process.stderr.close()
        fixture.send()
        return {"scenario": f"pipe-{scenario}", **fixture.finish(events)}


def connected_output(scenario: str, name: str, stderr=subprocess.PIPE):
    with running(scenario, stderr) as fixture:
        events = fixture.event_until("worker-started", 2)
        fixture.send()
        return {"scenario": name, **fixture.finish(events)}


def disconnected_pty():
    master, slave = open_pty()
    try:
        with running("pty-quiet-success", slave) as fixture:
            os.close(slave)
            slave = -1
            events = fixture.event_until("worker-started", 2)
            os.close(master)
            master = -1
            os.kill(fixture.process.pid, signal.SIGWINCH)
            fixture.send()
            return {"scenario": "pty-disconnected", **fixture.finish(events)}
    finally:
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)


def paused_pty(scenario: str, sent_signal: signal.Signals | None):
    master, slave = open_pty()
    try:
        with running(scenario, slave) as fixture:
            os.close(slave)
            slave = -1
            events = fixture.event_until("worker-started", 2)
            fixture.send()
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


def paused_worker_failure():
    scenario = "pty-backpressure-worker-failure"
    master, slave = open_pty()
    try:
        with running(scenario, slave) as fixture:
            events = fixture.event_until("worker-started", 2)
            # Open a separate description so the worker's stderr stays blocking.
            with open(os.ttyname(slave), "wb", buffering=0) as filler:
                os.set_blocking(filler.fileno(), False)
                for chunk in (b"x" * 4096, b"x"):
                    try:
                        while True:
                            os.write(filler.fileno(), chunk)
                    except BlockingIOError:
                        pass
            os.close(slave)
            slave = -1
            fixture.send()
            events.extend(fixture.event_until("progress-queued"))
            worker_pid = wait_for_worker(fixture.state)
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
                "workerPid": worker_pid,
                "workerAlive": process_exists(worker_pid),
            }
    finally:
        if slave >= 0:
            os.close(slave)
        if master >= 0:
            os.close(master)


def mixed_signals(first: signal.Signals, second: signal.Signals):
    scenario = f"pty-backpressure-mixed-{first.name.lower()}-{second.name.lower()}"
    master, slave = open_pty()
    try:
        with running(scenario, slave) as fixture:
            os.close(slave)
            slave = -1
            events = fixture.event_until("worker-started", 2)
            fixture.send()
            events.extend(fixture.event_until("progress-queued"))
            worker_pid = wait_for_worker(fixture.state)
            os.kill(fixture.process.pid, first)
            time.sleep(0.110)
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
        if scenario in {"missing-id", "wrong-id"}:
            events = fixture.event_until("worker-started", 2)
            fixture.send()
        else:
            events = []
        return {"scenario": scenario, **fixture.finish(events)}


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
    disconnected_pty(),
    paused_pty("pty-backpressure-success", None),
    paused_pty("pty-backpressure-sigint", signal.SIGINT),
    paused_pty("pty-backpressure-sigterm", signal.SIGTERM),
    paused_worker_failure(),
    mixed_signals(signal.SIGINT, signal.SIGTERM),
    mixed_signals(signal.SIGTERM, signal.SIGINT),
    cleanup_sigwinch(),
    simple_pty_process("single-saved-progress-interactive"),
    simple_process("single-saved-progress-ci"),
    simple_process("missing-id"),
    simple_process("wrong-id"),
    simple_process("repeated-main"),
]
if Path("/dev/full").exists():
    with open("/dev/full", "wb", buffering=0) as full_device:
        results.append(connected_output("worker-failure", "full-device", full_device))
print(json.dumps(results))
