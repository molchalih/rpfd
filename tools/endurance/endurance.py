#!/usr/bin/env python3
"""Drive one `rpf serve --stdio` through many session cycles, sampling its RSS."""

import argparse
import base64
import hashlib
import json
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
BINARY = REPO / "target" / "release" / "rpf"


class Refused(RuntimeError):
    """The daemon answered a request with an error and is still there."""


class Daemon:
    def __init__(self, binary):
        self.process = subprocess.Popen(
            [str(binary), "serve", "--stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.next_id = 0
        self.said = []
        self.listener = threading.Thread(target=self.listen, daemon=True)
        self.listener.start()

    def listen(self):
        for line in self.process.stderr:
            self.said.append(line.decode("utf-8", errors="replace").rstrip())

    def died(self, method, how):
        try:
            code = self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            code = None
        self.listener.join(timeout=10)
        told = " | ".join(self.said[-12:]) or "and said nothing on stderr"
        return RuntimeError(f"daemon {how} during {method} (exit {code}): {told}")

    def alive(self):
        return self.process.poll() is None

    def release(self, handle):
        """A daemon that has already gone must not replace the failure that took it."""
        try:
            self.call("close", handle=handle)
        except RuntimeError:
            if self.alive():
                raise

    def call(self, method, **params):
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        try:
            self.process.stdin.write((json.dumps(request) + "\n").encode())
            self.process.stdin.flush()
        except (BrokenPipeError, ValueError):
            raise self.died(method, "stopped reading its input") from None
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise self.died(method, "closed its output")
            message = json.loads(line)
            if message.get("id") != request["id"]:
                continue
            if "error" in message:
                raise Refused(f"{method}: {json.dumps(message['error'])}")
            return message["result"]

    def stop(self):
        if not self.process.stdin.closed:
            try:
                self.process.stdin.close()
            except (BrokenPipeError, ValueError):
                pass
        try:
            self.process.wait(timeout=30)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()
        self.listener.join(timeout=10)
        self.process.stdout.close()
        self.process.stderr.close()
        return self.process.returncode


class Sampler(threading.Thread):
    """Resident set size of one pid, in kilobytes, at a fixed interval."""

    MISSES_ALLOWED = 20

    def __init__(self, pid, interval):
        super().__init__(daemon=True)
        self.pid = pid
        self.interval = interval
        self.samples = []
        self.marks = []
        self.misses = 0
        self.started = time.monotonic()
        self.stopping = threading.Event()

    def run(self):
        unbroken = 0
        while not self.stopping.is_set():
            rss = self.read()
            if rss is None:
                self.misses += 1
                unbroken += 1
                if unbroken > self.MISSES_ALLOWED:
                    return
            else:
                unbroken = 0
                self.samples.append((time.monotonic() - self.started, rss))
            self.stopping.wait(self.interval)

    def read(self):
        done = subprocess.run(
            ["ps", "-o", "rss=", "-p", str(self.pid)], capture_output=True, text=True
        )
        text = done.stdout.strip()
        return int(text) if text else None

    def mark(self, cycle):
        self.marks.append((time.monotonic() - self.started, cycle))

    def stop(self):
        self.stopping.set()
        if self.is_alive():
            self.join(timeout=5)


def edited(payload, cycle):
    """One byte flipped, at a place that moves cycle by cycle, keeping the length."""
    flipped = bytearray(payload)
    flipped[cycle * 7919 % len(flipped)] ^= 0x01
    return bytes(flipped)


def encoded(payload):
    return base64.b64encode(payload).decode()


def reads_as_xml(daemon, handle, path):
    try:
        daemon.call("read", handle=handle, path=path, **{"as": "xml"})
    except Refused:
        return False
    return True


def patchable(daemon, handle, paths):
    """The first entry whose same-length rewrite a dry run settles as a patch."""
    for path in paths:
        payload = base64.b64decode(daemon.call("read", handle=handle, path=path)["bytes"])
        daemon.call("write", handle=handle, path=path, bytes=encoded(edited(payload, 0)))
        method = daemon.call("commit", handle=handle, dry_run=True, progress=False)["method"]
        daemon.call("discard", handle=handle)
        if method == "patch":
            return path
    return None


def workload(daemon, path, name):
    """One archive, the entries a cycle touches in it, discovered from its listing."""
    handle = daemon.call("open", path=path)["handle"]
    try:
        rows = daemon.call("list", handle=handle, recursive=True)
        files = [row for row in rows if row["kind"] != "directory" and row["len"]]
        by_len = lambda row: row["len"]
        top = sorted((row for row in files if ".rpf/" not in row["path"]), key=by_len)
        nested = sorted((row for row in files if ".rpf/" in row["path"]), key=by_len)
        if len(top) < 3 or not nested:
            raise SystemExit(f"{path}: needs three top-level entries and a nested archive")
        xml_read = next(
            (row["path"] for row in top if reads_as_xml(daemon, handle, row["path"])), None
        )
        if xml_read is None:
            raise SystemExit(f"{path}: no entry the daemon will read as xml")
        edit = patchable(daemon, handle, [row["path"] for row in top if row["path"] != xml_read])
        if edit is None:
            raise SystemExit(f"{path}: no entry a commit would patch in place")
        return {
            "name": name,
            "path": path,
            "small_reads": [row["path"] for row in top[:3]],
            "xml_read": xml_read,
            "edit": edit,
            "nested": [nested[0]["path"], nested[-1]["path"]],
            "rename": next(row["path"] for row in top if row["path"] != edit),
            "rebuilds": 0,
            "digests": set(),
            "cycles": 0,
            "commits": Counter(),
        }
    finally:
        daemon.release(handle)


def cycle(daemon, work, index, commit, rebuild):
    opened = daemon.call("open", path=work["path"])
    handle = opened["handle"]
    try:
        daemon.call("info", handle=handle)
        daemon.call("list", handle=handle, recursive=True)
        for entry in work["small_reads"]:
            daemon.call("read", handle=handle, path=entry)
        daemon.call("read", handle=handle, path=work["xml_read"], **{"as": "xml"})
        for entry in work["nested"]:
            daemon.call("read", handle=handle, path=entry)

        payload = base64.b64decode(daemon.call("read", handle=handle, path=work["edit"])["bytes"])
        written = edited(payload, index)
        work["digests"].add(hashlib.sha256(written).hexdigest())
        daemon.call("write", handle=handle, path=work["edit"], bytes=encoded(written))
        if commit:
            if rebuild:
                daemon.call("mkdir", handle=handle, path=f"endurance/{work['rebuilds']}")
                work["rebuilds"] += 1
            daemon.call("pending", handle=handle)
            result = daemon.call("commit", handle=handle, progress=False)
        else:
            daemon.call("mkdir", handle=handle, path="endurance/scratch")
            daemon.call(
                "write",
                handle=handle,
                path="endurance/scratch/new.xml",
                bytes=encoded(b"<x/>\n"),
                create=True,
            )
            daemon.call(
                "rename", handle=handle, **{"from": work["rename"], "to": work["rename"] + ".moved"}
            )
            daemon.call("commit", handle=handle, dry_run=True, progress=False)
            daemon.call("pending", handle=handle)
            result = daemon.call("discard", handle=handle)
        return result
    finally:
        daemon.release(handle)


def labelled(sources):
    """Each source under the label it is reported and copied by, refusing two that share one."""
    claimed = {}
    for source in sources:
        label = f"{source.parent.name}/{source.name}" if source.parent.name else source.name
        if label in claimed:
            raise SystemExit(
                f"two archives are both {label}: {claimed[label]} and {source}. "
                "One would overwrite the other and the run would measure one archive twice"
            )
        claimed[label] = source
    return claimed


def retained(pid):
    """What libmalloc holds dirty but empty, which is retention and not a leak."""
    try:
        done = subprocess.run(["vmmap", "-summary", str(pid)], capture_output=True, text=True)
    except OSError:
        return None
    lines = [" ".join(line.replace("see MALLOC ZONE table below", "").split()) for line in done.stdout.splitlines()]
    empty = [line for line in lines if "(empty)" in line]
    footprint = [line for line in lines if line.startswith("Physical footprint:")]
    return "; ".join(empty + footprint) or None


def loadavg():
    done = subprocess.run(["sysctl", "-n", "vm.loadavg"], capture_output=True, text=True)
    return done.stdout.strip() or "unknown"


def trend(samples):
    """Least-squares slope, in kilobytes per second, over the given samples."""
    if len(samples) < 3:
        return 0.0
    times = [point[0] for point in samples]
    values = [point[1] for point in samples]
    mean_t = statistics.fmean(times)
    mean_v = statistics.fmean(values)
    spread = sum((t - mean_t) ** 2 for t in times)
    if spread == 0:
        return 0.0
    return sum((t - mean_t) * (v - mean_v) for t, v in zip(times, values)) / spread


def report(sampler, cycles, elapsed, out):
    samples = list(sampler.samples)
    if not samples:
        print(f"no samples in {elapsed:.1f} s over {cycles} cycles; {sampler.misses} ps failures")
        return ""
    values = [point[1] for point in samples]
    tail = samples[len(samples) // 2 :]
    tail_values = [point[1] for point in tail]
    slope = trend(tail)
    per_cycle = slope * elapsed / cycles if cycles else 0.0

    deciles = []
    for index in range(10):
        chunk = values[len(values) * index // 10 : len(values) * (index + 1) // 10]
        if chunk:
            deciles.append((index, min(chunk), int(statistics.fmean(chunk)), max(chunk)))

    lines = [
        f"cycles          {cycles}",
        f"wall clock      {elapsed:.1f} s",
        f"samples         {len(samples)} at {sampler.interval} s, {sampler.misses} ps failures",
        f"rss first       {values[0]} KB",
        f"rss last        {values[-1]} KB",
        f"rss min / max   {min(values)} / {max(values)} KB",
        f"second-half     min {min(tail_values)}, mean {int(statistics.fmean(tail_values))}, max {max(tail_values)} KB",
        f"trend (2nd ½)   {slope:+.2f} KB/s, {per_cycle:+.2f} KB/cycle",
        "",
        "decile  min      mean     max",
    ]
    for index, low, mean, high in deciles:
        lines.append(f"{index:>6}  {low:<8} {mean:<8} {high}")
    text = "\n".join(lines)
    print(text)
    if out:
        Path(out).write_text(
            "seconds,rss_kb\n" + "\n".join(f"{t:.2f},{v}" for t, v in samples) + "\n"
        )
    return text


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cycles", type=int, default=500)
    parser.add_argument("--interval", type=float, default=0.5)
    parser.add_argument(
        "--archive",
        action="append",
        default=[],
        help="archive to drive; repeatable. Copied before use. Defaults to the two demo archives",
    )
    parser.add_argument(
        "--rebuild-every",
        type=int,
        default=10,
        help="one commit in N is structural, and so a rebuild rather than a patch",
    )
    parser.add_argument("--csv", help="write every RSS sample here")
    parser.add_argument("--binary", default=str(BINARY))
    args = parser.parse_args()

    given = args.archive or [
        Path.home() / "rpf-demo/test/test.rpf",
        Path.home() / "rpf-demo/test2/test2.rpf",
    ]
    sources = [Path(p).expanduser().resolve() for p in given]
    for source in sources:
        if not source.is_file():
            parser.error(f"no archive at {source}")
    if not Path(args.binary).is_file():
        parser.error(f"no rpf binary at {args.binary}; cargo build --release")

    subjects = labelled(sources)

    with tempfile.TemporaryDirectory(prefix="rpf-endurance-") as scratch:
        copies = []
        for label, source in subjects.items():
            copy = Path(scratch) / label
            copy.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, copy)
            copies.append((label, copy))

        started_at = loadavg()
        daemon = Daemon(args.binary)
        methods = Counter()
        works = []
        sampler = Sampler(daemon.process.pid, args.interval)
        started = time.monotonic()
        try:
            works = [workload(daemon, str(copy), label) for label, copy in copies]
            for work in works:
                print(
                    f"  {work['name']}: edit {work['edit']}, xml {work['xml_read']},"
                    f" nested {work['nested'][0]} + {work['nested'][1]}",
                    file=sys.stderr,
                )
            sampler.start()
            started = time.monotonic()
            commits = 0
            for index in range(args.cycles):
                work = works[index % len(works)]
                work["cycles"] += 1
                sampler.mark(index)
                commit = (index // len(works)) % 2 == 0
                made = sum(work["commits"].values())
                rebuild = commit and args.rebuild_every > 0 and made % args.rebuild_every == 0
                result = cycle(daemon, work, index, commit=commit, rebuild=rebuild)
                if commit:
                    commits += 1
                    method = result.get("method", "unreported")
                    methods[method] += 1
                    work["commits"][method] += 1
                if (index + 1) % 25 == 0:
                    rss = sampler.samples[-1][1] if sampler.samples else "no"
                    print(f"  {index + 1} cycles, rss {rss} KB", file=sys.stderr)
        finally:
            elapsed = time.monotonic() - started
            sampler.stop()
            held = retained(daemon.process.pid)
            code = daemon.stop()

        report(sampler, args.cycles, elapsed, args.csv)
        distinct = sum(len(work["digests"]) for work in works)
        print(f"edits           {distinct} distinct payloads over {args.cycles} cycles")
        taken = ", ".join(f"{count} {name}" for name, count in sorted(methods.items()))
        print(f"commits         {taken or 'none'}")
        print("per workload")
        width = max((len(work["name"]) for work in works), default=0)
        for work in works:
            took = ", ".join(f"{count} {name}" for name, count in sorted(work["commits"].items()))
            print(
                f"  {work['name']:<{width}}  {work['cycles']} cycles,"
                f" {len(work['digests'])} distinct payloads, {took or 'no commits'}"
            )
        print(f"load avg        {started_at} to {loadavg()}")
        if held:
            print(f"vmmap           {held}")
        print(f"daemon exit     {code}")
        return 0 if code == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
