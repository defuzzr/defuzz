# Limits and known gaps

## Audit

- The audit describes current files and settings, not what an agent actually did.
- Some checks read other profiles’ content, including memory and files used for duplicate hashes.
- Full audits can inspect discovered link targets; individual reads reject unexpected links.
- Reads may update access times; file sizes do not measure unique disk blocks.
- Scores and token figures are estimates, not provider measurements.
- Unsupported YAML readers or failed loader checks leave affected results unverified.
- Quick mode omits checks; timed-out checks are unverified, and some in-process work lacks the worker’s hard deadline.
- Default outward-walk limits and folder pruning are lifted by `--unbounded`; explicitly referenced folders can bypass pruning too.
- Credential-shaped names are withheld only for recognized shapes; SQLite reopening leaves a same-user replacement race.

## Creation

- Kits require a usable componentize command and provide folders and guidance rather than working application code.
- The component-library kit is Python-only.
- Keep secrets out of `.cargo/config.local.toml`, which the Rust template lists in `.worktreeinclude`.
- Closing the creation dialog leaves the job running; cancellation stops being available during publication.
- If replies are lost, check the project list before retrying; temporary polling failures do not stop the job.
- Expired unused proposals are cleaned on later proposal requests, and staging can remain after cleanup fails.
- A changed destination can cause refusal or partial publication; rollback may leave folders that need inspection.
- Publication does not guarantee crash durability.
- A same-user process can change a project root between operations despite no-follow writes within each operation.
- The .NET spaced-temporary-path workaround needs a space-free project path; otherwise set `TMPDIR` to a space-free path.
- Project identifiers and kit folders use ASCII; template folders preserve Unicode but not every case variant shares a name.

## Adoption and outputs

- An existing destination is reused only for a completed run from the same source; choose a new destination for unrelated folders.
- Remove only an incomplete copy Defuzz started before retrying; an unmarked copy is not a completed run.
- Inventory and rules outputs reject linked parents below home or temporary roots, even where ordinary adoption works.
- A running copy keeps writing through held handles if its destination moves; later refusal does not undo copied files.
- Later steps resolve the copy root again, so parent replacement between steps can redirect work.
