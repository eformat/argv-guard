# Arming guide

`LD_PRELOAD` arms only processes **started after it is set, by a process that
already has the lib mapped**. The veto fires at the `execve` made by a hooked
process — and no process can veto the exec that started it.

The consequences that bite in practice:

- an `export LD_PRELOAD=…` in `.bashrc` runs inside an already-running shell —
  the shell itself is never hooked, so its *direct* commands are unscanned
  (nested layers — `bash -c`, scripts — are covered)
- "open a new terminal" doesn't help by itself: the new bash inherits the
  *emulator's* environment, which predates arming
- an armed `systemctl --user` manager doesn't arm already-running apps either

| shell state | how the command gets exec'd | result |
|---|---|---|
| rc export only | direct | runs — server replies 401, no veto |
| rc export only | one layer deeper (`exec bash -c 'curl …'`) | BLOCKED |
| hooked shell (any route below) | direct | BLOCKED |

## Verify — the two checks that matter

```sh
# is THIS shell hooked? (ground truth, run in any shell)
grep -c libargvguard /proc/self/maps          # ≥1 = armed, 0 = unguarded

# does a secret-argv command get vetoed? (placeholder token)
curl -sS -H "Authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWX" https://api.github.com
# armed:   BLOCKED … Operation not permitted (exit 126)
# unarmed: HTTP 401 from the server — arming is not in this shell's ancestry
```

The one-liner self-test is **one exec layer deeper**, so it shows BLOCKED even
when the calling shell is not armed — green ≠ armed:

```sh
bash -c '/bin/true Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWX'
```

## Route 1 — every interactive shell (recommended)

End of `~/.bashrc`. The file check prevents a re-exec loop if the lib is ever
uninstalled, the maps check stops the second pass, `$-` leaves non-interactive
shells (e.g. `ssh host cmd`) alone. Also the only fix for SSH sessions: sshd
strips `LD_PRELOAD`, so this re-arms the remote interactive shell on login.

```sh
# argv-guard: arm this shell itself (one re-exec, loop-safe)
if [[ $- == *i* && -f "$HOME/.local/lib/argv-guard/libargvguard.so" ]] \
   && ! grep -q libargvguard /proc/self/maps 2>/dev/null; then
    export LD_PRELOAD="$HOME/.local/lib/argv-guard/libargvguard.so${LD_PRELOAD:+:$LD_PRELOAD}"
    exec bash
fi
```

## Route 2 — whole graphical session

`~/.config/environment.d/argv-guard.conf`, then re-login — session apps
(incl. terminal emulators) then carry the var, so every new terminal's shell
is hooked at exec:

```ini
LD_PRELOAD=/home/you/.local/lib/argv-guard/libargvguard.so
```

Apply to the **running** manager without re-login (newly launched apps only —
already-running emulators keep their old environment until they restart):

```sh
systemctl --user set-environment LD_PRELOAD=$HOME/.local/lib/argv-guard/libargvguard.so
dbus-update-activation-environment --systemd LD_PRELOAD=$HOME/.local/lib/argv-guard/libargvguard.so
```

Check what the user manager will hand to future services:

```sh
systemctl --user show-environment | grep LD_PRELOAD
```

## Route 3 — one shell, one-shot

```sh
export LD_PRELOAD="$HOME/.local/lib/argv-guard/libargvguard.so${LD_PRELOAD:+:$LD_PRELOAD}"
exec bash        # re-exec so THIS shell gets the lib at its own exec
```

## Bypass

`ARVGUARD_OFF=1 <command>` (per command) or unset entirely (session).
Prefix gotcha: the var must be in the exec'd process's *environment* —
`env ARVGUARD_OFF=1 curl -H <secret> …` is vetoed at the `env` exec (env's own
argv carries the secret; its environ doesn't have the flag yet). Prefix the
command directly, or export it in the shell first.

Hits log (redacted previews only — the full secret is never duplicated):
`~/.local/share/argv-guard/hits.log`.

## Known gaps

| covered | not covered (documented escapes) |
|---|---|
| every `execve`/`execveat` through libc in processes that inherit `LD_PRELOAD`: interactive shells, scripts, **opencode's bash-tool commands** | static binaries; glibc `posix_spawn`-style direct spawners (Rust/Go `std::process` — an *outer* `bash -c` string may escape, but the inner commands it runs are covered); `sudo`/setuid (kernel strips LD_PRELOAD); processes started before arming; a shell that only *exported* the var from its rc (its own direct execs — see Route 1); SSH sessions at the sshd layer (Route 1 covers the remote interactive shell) |

Retro-hooking an already-running process is kernel territory — that's
parked (eBPF LSM, see `~/.opencode/plan/argv-guard.md`), deliberately
not built.

## Proving non-collection (for auditors)

Falcon's `ProcessRollup2` telemetry is generated from the *running process* —
image + `/proc/PID/cmdline`. If no process with the curl image ever exists,
there is nothing to report. Three local proofs and one positive control.

**1. Kernel level: the exec syscall never fires.** The interception is
userspace (libc interposition), so the kernel never even sees the attempt.
Put the attempt in a script file first — the script's argv carries no token,
so your armed shell doesn't veto the *tracer* instead:

```sh
printf '%s\n' 'curl -H "Authorization: Bearer ghp_ABCDEFGHIJKLMNOPQRSTUVWX" https://api.github.com' > /tmp/veto-curl.sh
strace -f -e trace=execve,execveat -o veto-trace.txt bash /tmp/veto-curl.sh   # rc 126
grep -c 'execve("/usr/bin/curl"' veto-trace.txt                               # → 0
```

(If you ever see a curl execve here, the shell you ran it from was not armed
— see *Verify* above.)

Positive control — same rig, real exec, proving the method can see one:

```sh
strace -f -e trace=execve,execveat -o ctrl-trace.txt \
  bash -c 'curl -sS https://api.github.com -o /dev/null'
grep 'execve("/usr/bin/curl"' ctrl-trace.txt   # → execve("/usr/bin/curl", …) = 0
```

**2. Process level: no curl image in /proc, ever.** A real curl lives ~200 ms
(network round trip); hammer the veto while sampling /proc at full speed.
Measured on the reference box: 743 attempts, 1,911 full scans, 1.19 M comm
observations, 0 hits.

```sh
cat > /tmp/procscan.c <<'EOF'
// procscan <needle> <seconds> — sample /proc/*/comm at max speed
#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    struct timespec t0, now; clock_gettime(CLOCK_MONOTONIC, &t0);
    long scans = 0, obs = 0, hits = 0;
    for (;;) {
        DIR *d = opendir("/proc"); if (!d) return 1;
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
            char p[64]; snprintf(p, sizeof p, "/proc/%s/comm", e->d_name);
            int fd = open(p, O_RDONLY); if (fd < 0) continue;
            char b[64]; ssize_t n = read(fd, b, sizeof b - 1); close(fd);
            if (n <= 0) continue; b[n] = 0; obs++;
            if (strstr(b, argv[1])) { hits++; printf("HIT pid=%s comm=%s\n", e->d_name, b); }
        }
        closedir(d); scans++;
        clock_gettime(CLOCK_MONOTONIC, &now);
        if ((now.tv_sec - t0.tv_sec) + (now.tv_nsec - t0.tv_nsec) / 1e9 >= atof(argv[2])) break;
    }
    printf("full-scans=%ld comm-observations=%ld needle-hits=%ld\n", scans, obs, hits);
    return 0;
}
EOF
gcc -O2 -o /tmp/procscan /tmp/procscan.c
/tmp/procscan curl 2 > scan-out.txt &
end=$((SECONDS+1))
while (( SECONDS < end )); do bash /tmp/veto-curl.sh 2>/dev/null; done
wait; tail -1 scan-out.txt        # → full-scans=… comm-observations=… needle-hits=0
```

**3. The guard's own log** — written by the dying pre-exec child, redacted:

```sh
tail -1 ~/.local/share/argv-guard/hits.log
# 1794372589 exe=curl pattern=bearer-token arg=2 preview=Bearer ghp_AB…
```

**Boundary of the claim**: vetoed attempts never produce a curl process — the
forked child dies still wearing the shell's image (bash telemetry, which every
command produces anyway). *Allowed* curls — clean argv, or `ARVGUARD_OFF=1` —
create a real process and ship normally; that is by design. The final
cloud-side confirmation is one glance at the CrowdStrike console for the host:
the positive-control curl shows up; no event exists for any vetoed attempt.

## Uninstall (order matters)

```sh
systemctl --user unset-environment LD_PRELOAD     # if Route 2 live-apply was used
rm ~/.config/environment.d/argv-guard.conf        # if Route 2 was configured
# remove the self-arm block from your rc files
make uninstall                                    # or: rm -r ~/.local/lib/argv-guard/
```

Shells still carrying the var keep arming children until re-exec'd — `exec
bash` or a fresh terminal finishes the job.
