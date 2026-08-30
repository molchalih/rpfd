# rpf — router

Read this, then compute the address of what you need from the table below.
This file holds routing and invariants only; it owns no fact that a document
under `docs/` owns.

## Before writing code

Read `docs/conventions.md` in full before the first line of any change to
source, and check the finished diff against the review list at its end.

This holds for every contributor and for every delegated or automated task,
**including one scoped narrowly enough that the conventions look irrelevant to
it.** Narrow scope is where a layer boundary gets crossed by accident, because
the crossing is only visible from outside the task.

## Authority order

When two sources disagree, believe them in this order. Stop at the first that
can answer.

| # | Source | Note |
|---|---|---|
| 1 | Bytes in a real archive | A probe against `assets/` settles layout questions in seconds. Prefer it to every other row |
| 2 | Behaviour of the game or of FiveM loading the output | The only test of whether a rebuilt archive is correct |
| 3 | Reference implementations — `CodeWalker.Core`, and the crate published as `rpf-archive` / `rage-rpf` / `rpf-rs` | Read as specification, port with attribution. Never linked, never shipped: DR-007, superseding DR-005. **Those three names are one repository by one author, not three sources** — citing them severally triple-counts a single derivative work whose own test suite is self-roundtrip. Two implementations agreeing matters only when they are two. DR-012 |
| 4 | Community wikis | Frequently describe RPF2 where the reader assumes RPF7. Corroborate before use |
| 5 | These documents | Correct only as far as their stated verification status |

**Never quote a constant from `docs/rpf-format.md` whose Status column is not
`verified` as though it were established.** A row marked `secondary` was read
somewhere, not measured here.

Rationale and outcome: on 2026-08-26 a wiki-derived header layout
(`tocSize, entryCount, unknown, encFlag`) was carried into design discussion and
decoded the sample archive into nonsense — file offsets 220× the archive's own
length. A ten-line probe produced the real layout. Everything in
`docs/rpf-format.md` now carries a provenance marker for that reason.

## Ownership

| Question | Document | Where a new fact of this kind goes |
|---|---|---|
| What are we building, for whom, and what is deliberately excluded | `docs/approach.md` | Amend in place. A change to the scope boundary is also a decision record |
| What language, what components, how they connect | `docs/approach.md` | Amend in place; a change of component or binding mechanism needs a decision record |
| How code is written — boundaries, responsibility, error handling, naming, tests | `docs/conventions.md` | Amend in place. A convention whose reason has expired is deleted, not kept |
| How is the byte format laid out; what is compression, crypto, alignment, ordering | `docs/rpf-format.md` | A new row in the relevant table, with a Status marker and, when `verified`, the probe that established it |
| How is a metadata payload encoded once it is out of the archive — `RBF`, `PSO`, resource `Meta` | `docs/metadata-encodings.md` | A new row in the encoding's own table, with a Status marker and, when `verified`, the probe that established it. `docs/rpf-format.md` keeps the one-line summary and the recognition bytes, because classification is the container's question |
| What work is outstanding, in what order, and what is still unknown | `docs/backlog.md` | A new item under the owning track, or a new row in Open questions |
| What archives exist to test against, what each one is, and what it does and does not exercise | `docs/corpus.md` | A new row per archive, with its size, version, encryption tag and entry count, and a note on what class it covers |
| How a rebuilt archive is shown to load, and what a pass does and does not prove | `docs/acceptance.md` | Amend the procedure in place. A new observation is a step naming the command, the value it must show, and whether it has been executed here or only written |
| Which mutations of the container survive its own tests, and what each survivor means | `docs/mutants.md` | A sweep replaces the file. A survivor argued as equivalent-to-original states the argument, so the next sweep does not re-litigate it |
| What has been **exercised** against this code, where, and with what result — test counts per platform and per gate, fuzzing campaigns, continuous integration state | `docs/backlog.md`, "Where this stands" and Working notes | Amend in place, with the command and the date. **This class is exempt from that file's delete-when-done rule**: a campaign's result is not outstanding work, and deleting it loses the only record that something was ever run. Promote it to a document of its own when it outgrows a section |
| What the NG scheme is, where its key material lives, and which routes to it are open | `docs/ng-scheme.md` | Amend in place. A route that opens or closes is also a decision record |
| Why was an option chosen over its alternative | `docs/decisions/DR-NNN-<slug>.md` | Next free number. Never renumber, reword or delete — supersede |

A fact that fits no row above does not yet have a home; add the row before
adding the fact.

## Invariants

Each carries the reason it exists. A rule whose reason has expired should be
deleted, not obeyed out of habit.

| Rule | Why, and what it prevented |
|---|---|
| No assistant, model, or generation tooling is named anywhere in tracked content — code, comments, commits, documents | Work products read as authored. No trailers, no footers, no scaffolding directories |
| Branches land on `main` **squash-merged**, one commit per unit of work. `main` is linear: **no merge commits**, ever. A branch that produced several commits is squashed to the one unit it was for, or split into one commit per unit and rebased — never merged | Keeps the history readable at the granularity of decisions rather than keystrokes. A merge commit records no decision and no unit of work; it records only that two branches existed, which is a fact about process rather than about the archive format. This has already been broken twice by `git merge` of a delegated branch — `git merge --squash`, or `rebase`, is the only landing move |
| A delegated or automated task lands the same way as any other: its branch is squashed to one commit per unit, its worktree removed, and its branch deleted, before the next task starts | Parallel work produces branchy history and stale worktrees by default. Landing each unit as it finishes keeps `main` a list of decisions rather than a record of how many workers there were |
| A commit message is **one line and no body**: `type(scope): what changed`, lower case, no trailing full stop, 72 characters at most. Types are `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`, `build`, `ci`, `chore`; scopes are `core`, `cli`, `serve`, `client` or none. **Enforced, not merely stated**: `.githooks/commit-msg` refuses a malformed message (`git config core.hooksPath .githooks`, once per clone), and `ci.yml`'s `commits` job checks every commit a push or pull request adds, which holds for a clone that never enabled the hook | A log is read as a list, and a list is read by scanning the left edge. Reasoning does not belong in a commit because a commit is the one place it cannot be corrected — `docs/` is amendable and a decision record supersedes. Anything that needed a paragraph needed a document |
| No game archives, extracted assets, or key material in tracked content | Redistribution is not ours to grant, and `assets/` alone is 195 MB against a corpus whose tracked content is text. Enforced in `.gitignore` |
| Keys are extracted at runtime from the user's own install, never embedded | DR-006. Consequence: encrypted-archive tests cannot run in CI, and the backlog plans around that rather than around it being discovered late |
| A tool must refuse to write into a detected game install unless explicitly forced | Editing shipped archives in place breaks integrity checks. The tool is driven by automation that will do exactly what it is told |
| A claim of "verified" states the command and the value | See the Authority order note above for the failure that produced this rule |
| Code is written to `docs/conventions.md`, and a diff is checked against its review list before it is proposed | There is no code yet, so there is no surrounding source to absorb conventions from — the usual mechanism is simply absent. And this is byte-format work in which being wrong by sixteen bytes still inflates correctly, and fails only later, when the game declines to load the result |

## Extension

New document, new class, or new decision — add the ownership row first, in this
file, then the document. A document not reachable from the table above is
unfindable, and its findings will be derived again from scratch.
