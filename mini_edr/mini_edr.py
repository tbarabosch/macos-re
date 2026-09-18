#!/usr/bin/env python3
"""Tiny, educational macOS EDR built around Apple's eslogger."""

import argparse
import ctypes
import datetime as dt
import json
import os
import platform
import signal
import subprocess
import sys


ESLOGGER = "/usr/bin/eslogger"
EVENTS = ("exec", "fork", "exit", "create", "rename", "unlink", "btm_launch_item_add")
TEMP_DIRS = ("/private/tmp/", "/tmp/", "/var/tmp/")
INTERPRETERS = {"sh", "bash", "zsh", "osascript", "perl", "ruby"}
LAUNCH_DIRS = ("/Library/LaunchAgents", "/Library/LaunchDaemons")


def now():
    """Return the current UTC time as an ISO 8601 string."""
    return dt.datetime.now(dt.timezone.utc).isoformat()


def dig(value, *keys):
    """Read a sequence of keys from nested dictionaries."""
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def collect_paths(value):
    """Collect every string stored below a key named ``path``."""
    paths = []
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "path" and isinstance(child, str):
                paths.append(child)
            else:
                paths.extend(collect_paths(child))
    elif isinstance(value, list):
        for child in value:
            paths.extend(collect_paths(child))
    return paths


def event_view(message):
    """Extract the small view needed by the detection rules."""
    events = message.get("event", {})
    name = next(iter(events), "") if isinstance(events, dict) else ""
    payload = events.get(name, {}) if name else {}
    process = message.get("process", {})
    target = payload.get("target", {}) if name == "exec" else {}
    return {
        "name": name,
        "source_pid": dig(process, "audit_token", "pid"),
        "source_path": dig(process, "executable", "path") or "",
        "target_pid": dig(target, "audit_token", "pid"),
        "target_path": dig(target, "executable", "path") or "",
        "args": payload.get("args", []) if name == "exec" else [],
        "paths": collect_paths(payload),
    }


def redact_environment(message):
    """Remove execution environment variables before persistence."""
    exec_data = dig(message, "event", "exec")
    if isinstance(exec_data, dict):
        exec_data.pop("env", None)


def temporary_exec(event):
    """Match execution from a common temporary directory."""
    return event["name"] == "exec" and event["target_path"].startswith(TEMP_DIRS)


def inline_interpreter(event):
    """Match shells and interpreters executing inline source code."""
    name = os.path.basename(event["target_path"])
    interpreter = name in INTERPRETERS or name.startswith("python")
    return event["name"] == "exec" and interpreter and any(
        arg in {"-c", "-e"} for arg in event["args"][1:]
    )


def launch_item(event):
    """Match launch-item notifications and writes to launch directories."""
    if event["name"] == "btm_launch_item_add":
        return True
    return event["name"] in {"create", "rename"} and any(
        marker in path for path in event["paths"] for marker in LAUNCH_DIRS
    )


RULES = (
    ("exec-from-temporary-directory", "high", temporary_exec, "kill", "target"),
    ("inline-interpreter-execution", "medium", inline_interpreter, "alert", "target"),
    ("launch-item-persistence", "high", launch_item, "alert", "source"),
)


def open_log(path):
    """Open an append-only evidence log with owner-only permissions."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "a", encoding="utf-8")


def write_record(log, record):
    """Append and immediately flush one compact JSON Lines record."""
    log.write(json.dumps(record, separators=(",", ":"), ensure_ascii=False) + "\n")
    log.flush()


def process_path(pid):
    """Ask macOS for the executable path currently associated with a PID."""
    library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
    function = library.proc_pidpath
    function.argtypes = (ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32)
    function.restype = ctypes.c_int
    buffer = ctypes.create_string_buffer(4096)
    if function(pid, buffer, len(buffer)) <= 0:
        return ""
    return buffer.value.decode("utf-8", "replace")


def kill_process(pid, expected_path, eslogger_pid):
    """Send SIGKILL only after rejecting protected PIDs and path changes."""
    if not isinstance(pid, int) or pid <= 1:
        return "refused:invalid-pid"
    if pid in {os.getpid(), os.getppid(), eslogger_pid}:
        return "refused:protected-pid"

    actual_path = process_path(pid)
    if not actual_path:
        return "refused:not-running"
    if os.path.realpath(actual_path) != os.path.realpath(expected_path):
        return "refused:path-mismatch"

    return send_sigkill(pid)


def send_sigkill(pid):
    """Send SIGKILL and translate expected operating-system errors."""
    try:
        os.kill(pid, signal.SIGKILL)
        return "signal-sent"
    except ProcessLookupError:
        return "refused:not-running"
    except PermissionError:
        return "refused:permission-denied"
    except OSError as error:
        return f"error:{error.errno}"


def response_for(action, pid, path, enforce, eslogger_pid):
    """Return the configured response result for one rule match."""
    if action != "kill":
        return "not-configured"
    if not enforce:
        return "disabled"
    return kill_process(pid, path, eslogger_pid)


def emit_alert(rule_data, event, received, log, enforce, eslogger_pid):
    """Persist and print an alert for one matching rule."""
    rule, severity, _predicate, action, subject = rule_data
    pid = event[f"{subject}_pid"]
    path = event[f"{subject}_path"]
    response = response_for(action, pid, path, enforce, eslogger_pid)
    alert = {
        "kind": "alert",
        "received_at": received,
        "rule": rule,
        "severity": severity,
        "pid": pid,
        "path": path,
        "response": response,
    }
    write_record(log, alert)
    print(
        f"ALERT {severity} {rule} pid={pid} path={path} response={response}",
        flush=True,
    )


def inspect(message, log, enforce, eslogger_pid):
    """Store one event, evaluate every rule, and emit matching alerts."""
    received = now()
    event = event_view(message)
    redact_environment(message)
    write_record(log, {"kind": "event", "received_at": received, "event": message})
    for rule_data in RULES:
        if rule_data[2](event):
            emit_alert(rule_data, event, received, log, enforce, eslogger_pid)


def check_live_requirements():
    """Reject unsupported macOS versions and unprivileged live runs."""
    version = platform.mac_ver()[0]
    if platform.system() != "Darwin" or not version or int(version.split(".")[0]) < 13:
        raise RuntimeError("live collection requires macOS 13 or newer")
    if os.geteuid() != 0:
        raise RuntimeError("live collection must run as root")


def live_stream():
    """Start eslogger and return its child process and stdout stream."""
    check_live_requirements()
    child = subprocess.Popen(
        [ESLOGGER, *EVENTS],
        stdout=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )
    return child, child.stdout


def parse_args(argv=None):
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", metavar="CAPTURE", help="replay eslogger JSON Lines")
    parser.add_argument("--log", default="mini-edr.jsonl", help="evidence log path")
    parser.add_argument(
        "--enforce", action="store_true", help="enable configured response"
    )
    args = parser.parse_args(argv)
    if args.input and args.enforce:
        parser.error("--enforce cannot be used with --input")
    if args.input and os.path.abspath(args.input) == os.path.abspath(args.log):
        parser.error("input and log paths must differ")
    return args


def open_event_stream(input_path):
    """Open a replay capture or start the live eslogger sensor."""
    if input_path:
        return None, open(input_path, encoding="utf-8", errors="replace")
    return live_stream()


def process_lines(stream, log, enforce, eslogger_pid):
    """Decode and inspect every JSON object from an event stream."""
    for number, line in enumerate(stream, 1):
        try:
            inspect(json.loads(line), log, enforce, eslogger_pid)
        except (json.JSONDecodeError, AttributeError, TypeError):
            print(f"line {number}: invalid JSON event", file=sys.stderr)


def stop_child(child):
    """Terminate eslogger and force its exit after a short timeout."""
    if not child or child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=2)
    except subprocess.TimeoutExpired:
        child.kill()


def monitor(args):
    """Run replay or live monitoring and always clean up open resources."""
    child = None
    stream = None
    try:
        child, stream = open_event_stream(args.input)
        with open_log(args.log) as log:
            process_lines(stream, log, args.enforce, child.pid if child else -1)
        return child.wait() if child else 0
    except KeyboardInterrupt:
        return 130
    finally:
        stop_child(child)
        if stream:
            stream.close()


def exit_on_sigterm(*_unused):
    """Convert SIGTERM into a normal Python exit so cleanup still runs."""
    raise SystemExit(143)


def main(argv=None):
    """Validate the runtime, install signal handling, and run the monitor."""
    if sys.version_info < (3, 11):
        raise SystemExit("Python 3.11 or newer is required")
    signal.signal(signal.SIGTERM, exit_on_sigterm)
    return monitor(parse_args(argv))


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError) as error:
        raise SystemExit(f"mini-edr: {error}") from error
