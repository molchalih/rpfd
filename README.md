# rpf

A minimal, dependency-light toolchain for reading, editing and rebuilding
RAGE Package File (`.rpf`) archives from the terminal, from an editor, or from
an automated agent — without installing a GUI modding suite.

Status: **the container works.** An archive can be listed, read, edited and
rebuilt from the command line, including through nested archives. Metadata
conversion, encryption and the editor client are not built yet; see the backlog.

```
rpf info    dlc.rpf
rpf ls -R   dlc.rpf x64
rpf cat     dlc.rpf data/vehicles.meta
rpf put     dlc.rpf x64/vehicles.rpf/meringls63amg24.ytd new.ytd
rpf extract dlc.rpf tree/ && rpf pack tree/ dlc.rpf
rpf verify  dlc.rpf
rpf serve --stdio        # JSON-RPC, one object per line, edits held until commit
```

A path addresses through nesting in one string. Every reporting command takes
`--json`.

| Where to look | For |
|---|---|
| `AGENTS.md` | routing, authority order, repository policy |
| `docs/approach.md` | goal, scope boundary, stack, architecture |
| `docs/conventions.md` | how code is written; read before changing source |
| `docs/rpf-format.md` | format facts, each marked verified or not |
| `docs/backlog.md` | research and delivery backlog |
| `docs/decisions/` | decision records |
