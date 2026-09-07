# docgate

The documentation gate. Everything a clone receives as Markdown is checked
here — that every path it names is a path, that every link into a heading lands
on one, that every fence it opens closes, that the extractor still finds claims
to check, and that the surface is neither growing nor holding unspent budget.
Every `DR-NNN` cited from anywhere in the tracked tree is checked too, because a
citation a cloner cannot follow rots the same way a path does — wherever the
clone holds anything for one to resolve to; today it holds nothing, and the
check says so rather than passing or failing. `ci.yml`'s `documentation` job
runs it on every push and pull request.

```
tools/docgate/docgate.sh            check the tracked Markdown surface
tools/docgate/docgate.sh measure    print the numbers, change nothing, exit as check would
```

`measure` leaves the tree alone, but it does not launder the verdict: it prints
the same report and exits with the same status, because a wrapper that asked for
the numbers used to get green from a red tree.

Run it before a commit that touches any tracked page. It needs git, awk and a
shell and nothing else: this project ships a static binary with no runtime
prerequisite (DR-001), and a gate on that claim that needed a package manager
would be arguing against it.

## What it covers, and what it does not

The subject set for the path, anchor, fence and byte checks is
`git ls-files -- '*.md'` — exactly what a cloner receives, and nothing else.
That is `README.md`, `INSTALL.md`, and the README under each client, each tool
and `fixtures/`.

The citation check reads wider: every tracked text file, not only Markdown. A
`DR-NNN` in `ci.yml` or in a source file is read by the same cloner and points
at the same place. Reading all of it is most of what the gate costs — see the
measurement below.

All of `docs/`, and `AGENTS.md`, are untracked by design, so they are not here
to be checked. Reaching for them would gate what no cloner receives while
leaving what every cloner reads ungated. A reference from a tracked page into
one of them is withdrawn by `git check-ignore` and printed, never reported as
rot; `.gitignore` is where that decision is written down, in its own comments.

**The withdrawal is capped at 25% of the claims found, and it is all or
nothing.** An excuse removes a claim from the check, so an uncapped excuse
launders a broken corpus one ignored path at a time, however narrow each
withdrawal looks on its own. Over the cap the whole withdrawal is refused and
every claim is re-checked as though it had no excuse — all or nothing, so that
no `.gitignore` can be tuned to sit just under a partial cap.

A page may also name paths that are not in this repository at all — a server
tree, a path inside a game archive. Declare their shape in that page's front
matter and they are withdrawn too:

```
---
foreign-paths:
  - "resources/*"   # what these tokens really are
---
```

A declaration that is all wildcard is an opt-out rather than a shape, and one
that matches nothing in its own page is dead; both fail.

## Anchors

A link target keeps its anchor rather than having it cut off, because
`README.md#gone` names a real file and resolves cleanly while being a dead link:
a browser given an anchor it cannot find scrolls to the top of the page and
reports nothing, so the reader lands somewhere plausible and never learns the
section moved. Nothing else a reader has reports this.

A `.md` target — the naming page itself, for a bare `#anchor` — is read for its
headings, slugged the way GitHub slugs them, and for explicit `id=` and `name=`
attributes, which a page usually writes because the generated slug was
unusable. Fenced blocks are skipped, so a heading inside an example is not an
anchor.

## Citations

A `DR-NNN` resolves to a tracked record file under `docs/decisions/`, named for
the identifier, or to an id-led row in a tracked page whose front matter
declares which citations it resolves:

```
---
resolves-citations: ["DR-*"]
---
```

The declaration must name the tag up to the separator — `DR-*` is a namespace,
`DR*` and `*` are opt-outs and are refused by name — and it must lead at least
one row in the page that declares it, or it is a dead declaration.

An id leads a row when nothing runs on from it, so a row for `DR-007` is a row
and a link to the record file `DR-007-own-container` is not; and a row resolves only in a
page that declared it would, and only for an identifier its own declaration
covers, because a list of ids in a page that claims nothing is a list, not an
index.

**In this repository nothing declares one, and no record is tracked**, so no
`DR-NNN` can resolve here at all: the whole design record, the index of it
included, is working-tree material and a clone receives none of it. A check with
nothing to resolve against has examined nothing, so it reports `n/a — no yield`,
names the citations as unresolvable for a cloner by design, and counts in
neither direction — not a failure, which would leave the gate permanently red on
a decision the repository made deliberately, and not a pass, which would claim
the citations had been followed when none was. The report says so out loud,
because a check that simply goes quiet is indistinguishable from one that is
working. The moment a tracked page declares a namespace, or a record file is
tracked, every identifier in the tree is checked again exactly as above. The
`resolves-citations` guards are not part of this: neither can fire without a
declaration to police, so both stay armed whatever the yield.

## What a failure means

| Report | What to do |
|---|---|
| a declared root names no tracked directory | Rename it on the `roots` line, then in the pages. The directory moved, and every fenced command line rooted at it is stale — including the ones a root derived from the tree would have gone quiet about |
| a fence is never closed, or a closing fence carries trailing text | Fix the page. One unbalanced fence hid 86% of `fixtures/README.md` on GitHub, in a file read by eye more than once |
| the untracked-by-design withdrawal is refused | Track what the shipped pages point at, or stop pointing at it. The excuse is over its cap and is carrying the check rather than footnoting it; every claim below is now reported as though it had no excuse |
| a path claim resolves to no tracked path | Fix the path, or declare its shape as foreign. This is the rot the gate exists for: a command line still naming a directory renamed three commits earlier |
| a `foreign-paths` declaration is all wildcard, or matches nothing | Give it a shape, or delete it. Neither an opt-out nor a dead glob is a declaration |
| a `resolves-citations` declaration wildcards away the tag, or leads no row | Name the tag up to the separator, and put a row for it in this page. A namespace resolving every identifier withdraws a citation with nothing like the excuse cap above it |
| a link names a heading that is not there | Fix the anchor, or restore the heading. The link resolves to the right file and the wrong place in it, and says nothing when it does |
| a `DR-NNN` citation resolves to nothing | Track the record it names, or a page declaring the namespace and leading a row for it, or delete the citation. A reference a cloner cannot follow is worse than none: it reads as a promise that it is followable. Reported only when something in the clone could have resolved it — see the row below |
| citations report `n/a — no yield` | Nothing. No tracked page declares a namespace and no record is tracked, so every `DR-NNN` is unresolvable for a cloner by design; the check examined nothing and counts neither way. It bites again the moment either appears |
| the extractor found fewer claims than the floor | Look at `docgate.sh`, not at the documentation. A gate that checks nothing passes silently |
| the surface is over its byte budget | Cut something, or raise the budget and say in the commit what the extra bytes buy |
| the surface is under its byte budget | Lower the budget to what was measured. Banked headroom is how a budget becomes a ceiling nobody has looked at — the next page grows into it in silence |

## The three lines in budget.txt

`budget.txt` holds them, one per line, with the measurement or the argument that
set each. They are there rather than in the script so that moving one is a line
in a diff a reviewer can argue with — growth is a reviewed decision, not a side
effect.

`claims` is the floor the extractor must clear. Lowering it is a claim about the
documentation and needs the measurement that supports it; the usual cause is the
script.

`bytes` is the tracked Markdown surface, and the gate fails **both above and
below** it. That is what makes it a ratchet rather than a ceiling: the number
only ever moves down unless a change argues it up, and every documentation
change is expected to move the line. The cost is one line in the diff of every
documentation change, which is the same line the change already owed a reviewer.

`roots` is the top-level entries a command line inside a fenced block may be
rooted at. Rooting is what keeps a JSON body, an archive-internal path or a
shell variable out of the claims. It is declared rather than derived from
`git ls-files`, because derived meant a renamed directory stopped being a
subject instead of being reported: every command line naming `tools/` went
unread the moment `tools/` was gone. A declared root cannot be satisfied by
deleting what it names, so a rename fires here and in the pages both.

## What it measures now

`./tools/docgate/docgate.sh measure`, 2026-09-07: **11 tracked Markdown files,
113 path claims, and 25 claims withdrawn as untracked by design — 22.1% of 113,
under the 25% cap**. Fourteen more are withdrawn across five pages by their own
`foreign-paths` declarations, and those never enter the count the cap is taken
against. The citation pass finds **106 identifiers and reports no yield**,
because nothing tracked can resolve one.

`time ./tools/docgate/docgate.sh`, same day and tree: **0.34 to 0.40 s real over
three runs**, up from 0.12 s before the citation pass, which reads all 4.1 MB of
tracked text rather than the 96 KB of Markdown the other checks see. That is
most of the run and it is worth it, and the gate is still cheap enough to run
before every commit, which is the only budget it has.

Both numbers are of the tree, not of the gate, and go stale on their own. The
byte total is deliberately not restated here: `budget.txt` owns it, and a second
copy is a second thing to forget.
