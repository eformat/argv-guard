# argv-guard

*Stop sending your credentials to CrowdStrike.*

**LD_PRELOAD execve veto** — blocks any command execution whose argv carries
secret-shaped tokens (GitHub/Slack/OpenShift/AWS keys, bearer tokens, private
key blocks) before the process — and therefore before Falcon's few-seconds
telemetry ship — ever happens.

**Overhead: ~130–300 µs per exec** — dynamic-linker load of the lib dominates;
the argv scan itself is sub-µs. You only ever notice it when it blocks.

Companion to the argv-hygiene rule in `~/.config/opencode/AGENTS.md`: the rule
tells *us* not to inline secrets; this enforces it at the exec boundary,
including for opencode's bash-tool commands.

## The one design fact

The shell expands `$VAR`/`$(...)` **before** exec, and the child needs its real
argv — so redact-and-continue is impossible. The guard is a **veto**: the
command fails loudly before capture, which is the point.

## Quick start

```sh
make install                     # build + copy to ~/.local/lib/argv-guard/
```

**Arm it** — one env var, but *where* you put it decides what gets guarded.
Copy-paste blocks and the verify commands: **[docs/arming.md](docs/arming.md)**

| you want | do this |
|---|---|
| every interactive shell, incl. SSH | self-arm block at the end of `~/.bashrc` |
| whole graphical session | `~/.config/environment.d/argv-guard.conf`, re-login |
| just this one terminal | export + `exec bash` |

Verify the shell you're in (the only check that matters):

```sh
grep -c libargvguard /proc/self/maps        # ≥1 = armed, 0 = your execs are unguarded
```

Self-test (expect BLOCKED — but it runs one exec layer deeper, so green does
**not** prove the calling shell is armed; see [docs/arming.md](docs/arming.md)):

```sh
bash -c '/bin/true Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWX'
```

Bypass: `ARVGUARD_OFF=1 <command>` (prefix the command directly — the `env`
wrapper form gets vetoed first). Hits log (redacted previews only):
`~/.local/share/argv-guard/hits.log`.

## Coverage

| covered | not covered (documented escapes) |
|---|---|
| every `execve`/`execveat` through libc in processes that inherit `LD_PRELOAD`: interactive shells, scripts, **opencode's bash-tool commands** | static binaries; glibc `posix_spawn`-style direct spawners; `sudo`/setuid; processes started before arming; rc-export-only shells; SSH at the sshd layer — full list in [docs/arming.md](docs/arming.md) |

The escapes are why future (eBPF LSM, parked) exists — see
`~/.opencode/plan/argv-guard.md`.

## Golden-rule compliance (what this deliberately is NOT)

- pure userspace: one cdylib + one shell export line. No kernel modules, no
  eBPF, **no interaction with falcon of any kind**, no network listeners, no
  daemons. Everything lives in `$HOME`.
- to falcon this is invisible-by-schema: ProcessRollup2 carries argv, not env —
  and the guard's own argv is just the exe path.
- the artifact class is "a user's shell safety script", same as a bash alias.

## Patterns (v2 — curated from the OSS scanners, see `docs/matcher-research.md`)

~50 rules in three layers, all allocation-free byte scans:

1. **Provider prefixes + tail-shape** (ported/curated from gitleaks' 222
   rules): GitHub, GitLab, OpenAI, Anthropic, AWS, GCP, HuggingFace, npm/PyPI,
   Stripe, Shopify, Slack, Vault, Docker, Notion, Atlassian, Doppler, …
2. **Structural specials**: JWT (`eyJ`+40), `Basic `/`Bearer ` base64, PEM
   blocks, `Authorization:` header values, OpenShift `sha256~`.
3. **Keyword rules**: `token/password/secret/api_key/credential/auth` +
   `=`/`:` + ≥16-char value — with the letter-follows-keyword FP killer
   (`author=`, `keyboard`, `auth_file=` all safe without a stopword list).

Per-arg scan cap 2 KiB, per-exec 64 KiB — worst case stays sub-millisecond.
No pattern-file loading: the hot path is dumb and auditable in one screen.

## Testing

```sh
cargo test                 # matcher unit tests (hits + false positives + boundaries)
./test/integration.sh      # builds the .so, then pass/block/bypass/overhead cases
```

## Makefile

| target | what |
|---|---|
| `build` / `debug` | release / dev compile |
| `test` | unit tests + full integration script |
| `clippy` | `cargo clippy -- -D warnings` (zero-warning standard) |
| `fmt` | rustfmt |
| `install` | build + copy to `~/.local/lib/argv-guard/`, honours `DESTDIR`/`PREFIX` |
| `uninstall` / `clean` | remove the lib / `cargo clean` |

## Prior art

- [Snoopy](https://github.com/a2o/snoopy) — LD_PRELOAD execve *logger* (we flip log→veto)
- [bash-preexec](https://github.com/rcaloras/bash-preexec) + a zsh secret-filter plugin — shell-tier guards
- [Tetragon](https://tetragon.io/) — eBPF LSM argv-match + enforcement at k8s scale (our parked future)
- git-secrets / gitleaks / trufflehog — content scanners, different layer

## Status / repo conventions

- License: **MIT** — see [LICENSE](LICENSE) (matches `license = "MIT"` in Cargo.toml)
- the assistant scaffolds and edits; the human runs `git init` + commits
- uninstall: [docs/arming.md § Uninstall](docs/arming.md#uninstall-order-matters)
