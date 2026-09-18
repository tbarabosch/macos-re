# mini-edr-macos

`mini-edr-macos` is an educational macOS Endpoint Detection and Response proof
of concept. One standard-library Python file starts Apple's `eslogger`, stores
sanitized Endpoint Security notifications as JSON Lines, evaluates three small
detection rules, and can send one guarded response.

This is a learning implementation focused on a small, inspectable event path.
`eslogger` provides notifications after an operation has happened, and its JSON
schema can change without warning. A production Endpoint Security client adds
the integrity, prevention, compatibility, and operational controls that sit
outside this experiment.

## Requirements

- macOS 13 or newer
- Python 3.11 or newer
- root for live collection
- Full Disk Access for the responsible terminal or host process

There are no third-party Python dependencies.

## Run

Use the exact path of the Python interpreter you trust. Running source from a
writable checkout as root deserves the same care as running any other root
script.

```bash
sudo "$(command -v python3)" mini_edr.py
```

Events and alerts are appended to `mini-edr.jsonl`, which is forced to mode
`0600`. Choose another path with `--log`.

The default is alert-only. `--enforce` allows only the temporary-directory
execution rule to send `SIGKILL` after the PID's current executable path has
been checked with `proc_pidpath`:

```bash
sudo "$(command -v python3)" mini_edr.py --enforce
```

Replay a raw `eslogger` capture without root or response actions:

```bash
python3 mini_edr.py --input capture.jsonl --log replay.jsonl
```

The script subscribes to `exec`, `fork`, `exit`, `create`, `rename`, `unlink`,
and `btm_launch_item_add`. Its rules flag:

- execution from `/private/tmp`, `/tmp`, or `/var/tmp`;
- shells and interpreters using inline-code flags such as `-c` or `-e`;
- launch-item additions or writes below LaunchAgents and LaunchDaemons paths.

Only the first rule has a configured response. The other two are intentionally
alert-only because they are broad signals with common legitimate causes.

## Data and safety

The log contains one compact JSON object per line. Event records retain the
original `eslogger` object except for `event.exec.env`, which is removed because
environment variables often contain credentials. Command-line arguments remain
in the log and can also contain sensitive data. Logs have no rotation or
retention policy; delete them when the experiment is finished.

Even with `proc_pidpath`, response has a time-of-check-to-time-of-use race. A
successful `os.kill` call means only that the signal was sent. The monitored
operation has already occurred because `eslogger` exposes `NOTIFY`, not `AUTH`,
events. Keep the default alert-only mode unless you understand those limits.

## Benign demonstrations

Run demonstrations in another terminal while the monitor is active. Do not use
malware on a normal workstation.

```bash
demo_dir="$(mktemp -d /private/tmp/mini-edr-demo.XXXXXX)"
cp /bin/sleep "$demo_dir/sleep"
"$demo_dir/sleep" 10
rm -f "$demo_dir/sleep"
rmdir "$demo_dir"
```

```bash
/bin/zsh -c 'sleep 1'
```

For the persistence-path rule, create an inert file and remove it without ever
loading it with `launchctl`:

```bash
demo_plist="$HOME/Library/LaunchAgents/com.example.mini-edr-demo.plist"
touch "$demo_plist"
rm -f "$demo_plist"
```

## Scope and next steps

The experiment focuses on the smallest useful path from macOS telemetry to a
detection and an explicit response. A larger implementation could add
pre-execution decisions, a stable schema adapter, process-tree correlation,
storage and rotation, YARA enrichment, network telemetry, quarantine, service
installation, code signing, tamper protection, remote collection, and fleet
management.
