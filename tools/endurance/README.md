# endurance

Drives one `rpf serve --stdio` through many open/read/edit/commit/close cycles
and samples that process's resident set size throughout, to answer whether a
long-lived daemon holds steady or grows. The findings are in
`docs/endurance.md`.

## Running it

```
cargo build --release
python3 tools/endurance/endurance.py --cycles 2000
```

No arguments are required. Archives are **copied** to a temporary directory
before anything is committed to them, and the copies go with it; the originals
are never opened for writing. Each copy sits under its source's own directory
name, and that pair — directory and file name, `rmrp_volgas/dlc.rpf` — is what
the run reports each workload by, because the corpus holds many archives named
`dlc.rpf` and a bare file name distinguishes none of them. Two archives that
would still share one such name are **refused by name before the run starts**,
rather than one silently overwriting the other and the run measuring one
archive twice. `--archive PATH`, repeatable, replaces the two demo archives it
defaults to; any archive will do, since what a cycle touches is discovered from
the archive's own listing before the run starts — the three smallest top-level
entries, the first that answers a read as XML, the smallest and largest entry
inside a nested archive, and, as the entry every cycle rewrites, the first
whose same-length edit a dry run settles as a patch rather than a rebuild. An
archive with no nested archive, or none of those entries, is refused rather
than measured.

`--interval` is the sampling period in seconds, `--rebuild-every N` makes one
commit in N structural — and so a rebuild rather than a patch — and `--csv FILE`
writes every sample.

## What it reports

Resident set size first, last, minimum and maximum; the same over the run's
second half; a least-squares trend through that half in kilobytes per second
and per cycle; and the deciles of the run, which is where a plateau shows
itself. Then how many distinct payloads the run committed, which is what says
the workload varied; the tally of commits that patched against those that
rebuilt, which is a total over the run and says nothing about how either fell
across the archives; the same three counts per workload, which is what says
every archive named was actually driven, how the cycles divided between them,
and that `--rebuild-every` held for each subject rather than only for their
sum; and the load average at each end of the run, because nothing here has the
box to itself. On macOS it ends with `vmmap -summary`'s `(empty)` rows, which
say how much of the total is dirty memory the allocator is holding for reuse
rather than anything the daemon can still reach.
