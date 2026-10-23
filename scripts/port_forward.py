"""Owned kubectl process with observed listener and application readiness.

Only readiness probes are retried. Application requests are never replayed.
"""
from collections import deque
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time

import httpx


class PortForward:
    def __init__(self, command, *, log_path=None):
        self.command = command
        self.log_path = Path(log_path) if log_path else None
        self.lines = deque(maxlen=60)
        self.changed = threading.Condition()
        self.port = None
        self.process = None

    def __enter__(self):
        options = {'creationflags': subprocess.CREATE_NO_WINDOW} if os.name == 'nt' else {}
        self.process = subprocess.Popen(self.command, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, encoding='utf-8', errors='replace', **options)
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()
        return self

    def _read(self):
        try:
            for line in self.process.stdout:
                with self.changed:
                    self.lines.append(line.rstrip())
                    match = re.search(r'Forwarding from 127\.0\.0\.1:(\d+) ->', line)
                    if match:
                        self.port = int(match[1])
                    self.changed.notify_all()
        finally:
            with self.changed:
                self.changed.notify_all()

    def diagnostics(self):
        with self.changed:
            return '\n'.join(self.lines)

    def wait_ready(self, probe, *, timeout=20, cancelled=None):
        deadline = time.monotonic()+timeout
        last = 'listener not observed'
        while True:
            if cancelled is not None and cancelled.is_set():
                raise InterruptedError('Port-forward readiness cancelled')
            if self.process.poll() is not None:
                self.reader.join(timeout=1)
                raise RuntimeError(f'Port-forward exited ({self.process.returncode}): {self.diagnostics()}')
            if self.port is not None:
                try:
                    if probe(self.port) and self.process.poll() is None:
                        return
                    last = 'application probe did not return expected response'
                except (httpx.TransportError, OSError) as error:
                    last = type(error).__name__
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                raise TimeoutError(f'Port-forward application readiness timed out: {last}; {self.diagnostics()}')
            # Bounded condition polling, not an assumed startup/recovery delay.
            with self.changed:
                self.changed.wait(min(.1, remaining))

    def __exit__(self, *exc):
        if self.process.poll() is None:
            self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(timeout=5)
        self.reader.join(timeout=2)
        self.process.stdout.close()
        if self.log_path:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log_path.write_text(self.diagnostics()+'\n', encoding='utf-8')


def supervise_forwards(processes, start_forward, stop):
    """Replace only exited owned children; a cancelled replacement is reaped."""
    while not stop.wait(.1):
        for index, forward in enumerate(processes):
            if stop.is_set():
                return
            if forward.process.poll() is None:
                continue
            forward.__exit__(None, None, None)
            if stop.is_set():
                return
            try:
                replacement = start_forward(index)
            except Exception as error:
                if stop.is_set():
                    return
                print('Port-forward recovery failed: '+type(error).__name__, file=sys.stderr, flush=True)
                continue
            if stop.is_set():
                replacement.__exit__(None, None, None)
                return
            processes[index] = replacement
