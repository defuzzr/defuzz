# Defuzz

Defuzz helps beginners start or tidy projects with Hermes Agent using templates, folder rules and adopted copies.
It also checks project structure and audits Hermes settings and data.

## Requirements

- Linux only
- Python 3.13 or newer
- Hermes Agent 0.23.0 or newer
- Git

## Install

```bash
hermes plugins install defuzzr/defuzz
hermes plugins enable defuzz
```

## Use

Open **Defuzz** in the Hermes desktop sidebar, or list the available project starters:

```bash
hermes defuzz list
```

## What it does on your machine

- **Reads:** Audits the Hermes home read-only (settings, memory, skills, scheduled jobs and databases), selected projects, referenced files and parent context, and startup settings in your home folder: shell and Git configuration, systemd user units, autostart entries, pip, npm and cargo settings, and Python site customisation. Credential stores are only checked for presence. Session text is opt-in. Adopt and scan read the folder you give them.
- **Writes:** Uses `<Hermes home>/plugin-data/defuzz/`, creates projects or adopts copies, saves chosen outputs, saves your projects-folder setting in Hermes's `config.yaml` under its own plugin entry, and registers created projects with Hermes. Confirmed lint-tool setup installs into `~/.local/opt/defuzz`. Placement hooks route new agent writes in trusted projects by default.
- **Runs:** Git, template checks during creation, lint tools when asked, and optional `hermes componentize`; checks and lint can execute project code with your permissions, without a sandbox.
- **Network:** Confirmed lint-tool setup downloads tools/SDKs from official sources with pinned checksums (hosts in `setup_manifest.py`); checks/lint may contact registries. `rules`/`run` can send an inventory summary to your configured model through Hermes in one optional call; `--deterministic` skips it.
- **Background processes:** Workers run within the command or desktop job; Defuzz installs no persistent background service.
- **Credentials and telemetry:** Defuzz stores no credentials and sends no telemetry; model access uses Hermes. External tools retain their own configuration, credentials on disk and network behavior.

[What it does, with evidence](docs/DISCLOSURE-EVIDENCE.md) · [Known limits](docs/limits.md)

## Uninstall

Run `hermes plugins remove defuzz`.
Its plugin-data folder and tools installed in `~/.local/opt/defuzz` (or `DEFUZZ_INSTALL_ROOT`) remain; optional PowerShell modules, outputs, staging leftovers and shared caches may remain too.
Projects are yours and are not touched by uninstalling the plugin.

**Licence:** [MIT](LICENSE), copyright (c) 2026 defuzzr; Hermes Agent attribution in [NOTICE](NOTICE).

**Reporting:** [Open an issue](https://github.com/defuzzr/defuzz/issues) with your command, Hermes version and output, after removing private paths, names and secrets.
