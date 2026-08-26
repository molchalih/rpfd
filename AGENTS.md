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
| 3 | Reference implementations — `CodeWalker.Core`, the `rpf-archive` / `rage-rpf` crates | Read as specification, port with attribution. Never linked, never shipped: DR-007, superseding DR-005 |
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
| What work is outstanding, in what order, and what is still unknown | `docs/backlog.md` | A new item under the owning track, or a new row in Open questions |
| Why was an option chosen over its alternative | `docs/decisions/DR-NNN-<slug>.md` | Next free number. Never renumber, reword or delete — supersede |

A fact that fits no row above does not yet have a home; add the row before
adding the fact.

## Invariants

Each carries the reason it exists. A rule whose reason has expired should be
deleted, not obeyed out of habit.

| Rule | Why, and what it prevented |
|---|---|
| No assistant, model, or generation tooling is named anywhere in tracked content — code, comments, commits, documents | Work products read as authored. No trailers, no footers, no scaffolding directories |
| Branches land on `main` **squash-merged**, one commit per unit of work | Keeps the history readable at the granularity of decisions rather than keystrokes |
| No game archives, extracted assets, or key material in tracked content | Redistribution is not ours to grant, and `assets/` alone is 195 MB against a corpus whose tracked content is text. Enforced in `.gitignore` |
| Keys are extracted at runtime from the user's own install, never embedded | DR-006. Consequence: encrypted-archive tests cannot run in CI, and the backlog plans around that rather than around it being discovered late |
| A tool must refuse to write into a detected game install unless explicitly forced | Editing shipped archives in place breaks integrity checks. The tool is driven by automation that will do exactly what it is told |
| A claim of "verified" states the command and the value | See the Authority order note above for the failure that produced this rule |
| Code is written to `docs/conventions.md`, and a diff is checked against its review list before it is proposed | There is no code yet, so there is no surrounding source to absorb conventions from — the usual mechanism is simply absent. And this is byte-format work in which being wrong by sixteen bytes still inflates correctly, and fails only later, when the game declines to load the result |

## Extension

New document, new class, or new decision — add the ownership row first, in this
file, then the document. A document not reachable from the table above is
unfindable, and its findings will be derived again from scratch.
