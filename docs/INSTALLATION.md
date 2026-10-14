# Source installation and daily CLI use

Banshee runs local analysis without uploading input. These installers build the
checkout on your machine and copy only its executable into a chosen prefix. They
do not download a prebuilt executable, run a curl pipeline, change PATH, install
completion files, or require administrator/root access. Cargo may download locked
build dependencies on the first build; CLI analysis itself works offline.

## Prerequisites

- Rust/Cargo: stable Rust meeting `Cargo.toml`'s minimum (currently 1.88), with the
  repository's `rust-toolchain.toml` honored. Check `cargo --version` and
  `rustc --version` in a fresh terminal after installing Rust.
- Windows: PowerShell 7 (`pwsh`) and Visual Studio Build Tools with **Desktop
  development with C++**, including MSVC and the Windows SDK. Use native Windows
  Rust for the PowerShell installer.
- Linux: a native C/C++ compiler, linker, `make`, `pkg-config`, the liblzma
  development headers, Python 3, and standard Unix utilities. On Debian/Ubuntu:
  `sudo apt-get install build-essential pkg-config liblzma-dev python3`.
  Python 3 parses Cargo's JSON output and safely resolves paths.
- macOS: Xcode command line tools, Python 3, `pkg-config`, and XZ/liblzma.
  With Homebrew, run `brew install xz pkg-config python` before building.
  The shell scripts avoid GNU-only
  flags; successful script checks do not imply release support for every Mac
  architecture. Build and run the binary on your actual host before relying on it.

Work from a trusted local source checkout. `--locked` preserves `Cargo.lock`;
installation does not change package versions. WSL needs its own Linux Rust
toolchain and installation prefix: a Windows `.exe` is not a Linux installation.

XZ inspection uses liblzma. When the release executable links it dynamically,
the matching liblzma library must remain installed at runtime; copying only the
binary to another machine does not carry that dependency with it. On macOS keep
Homebrew's `xz` installation available; on Linux retain your distribution's
liblzma runtime package. Inspect `otool -L /path/to/banshee` on macOS or
`ldd /path/to/banshee` on Linux to see the dependencies of your actual build.

## Windows (PowerShell 7)

From the repository root:

```powershell
pwsh -NoProfile -File ./scripts/install.ps1 -Help
pwsh -NoProfile -File ./scripts/install.ps1 -Prefix "$HOME/.local"
& "$HOME/.local/bin/banshee.exe" --version
& "$HOME/.local/bin/banshee.exe" --help
# Optional: make it available by name in this terminal session only.
$env:PATH = "$HOME/.local/bin;$env:PATH"
banshee decode base64 aGVsbG8=
```

Choose any writable prefix, including one containing spaces. The default is
`$env:PREFIX` when nonempty, otherwise `$HOME/.local`; explicit `-Prefix` wins.
Relative prefixes resolve against your current directory, even when the installer
is invoked by absolute path from outside the repository. The installer always
builds at the repository root so its Cargo configuration is used.

```powershell
# Explicitly update an existing installation from the current checkout.
pwsh -NoProfile -File ./scripts/install.ps1 -Prefix "$HOME/.local" -Force
# Reuse an already built local release binary, without rebuilding it.
pwsh -NoProfile -File ./scripts/install.ps1 -Prefix "$HOME/.local" -SkipBuild -Force
```

For persistent command discovery, add the chosen `bin` directory to your **user**
Path through Windows Environment Variables and open a fresh terminal. Check
`Get-Command banshee -All` if a different installation takes precedence.

## Linux / WSL (POSIX shell)

```sh
sh scripts/install.sh --help
sh scripts/install.sh --prefix "$HOME/.local"
"$HOME/.local/bin/banshee" --version
"$HOME/.local/bin/banshee" --help
# Optional: make it available by name in this terminal session only.
export PATH="$HOME/.local/bin:$PATH"
banshee decode base64 aGVsbG8=
```

The default prefix is nonempty `$PREFIX`, otherwise `$HOME/.local`. Explicit
`--prefix` wins. For a persistent PATH, add the export above to your shell's startup
file yourself. Check `command -v banshee` to see which installation is selected.
The same `sh` commands work on macOS with the prerequisites above.

```sh
sh scripts/install.sh --prefix "$HOME/.local" --force
sh scripts/install.sh --prefix "$HOME/.local" --skip-build --force
```

## Build directories and replacement policy

Normal installation invokes `cargo build --release --locked --bin banshee` with
the native host explicitly selected using `--target`. It uses the executable
reported by Cargo, respecting `CARGO_TARGET_DIR`, `CARGO_BUILD_TARGET_DIR` and
Cargo configuration such as `[build] target-dir`. A configured cross-compilation
default is overridden to produce a binary for the machine running the installer.

```powershell
$env:CARGO_TARGET_DIR = 'C:/build caches/banshee'
pwsh -NoProfile -File ./scripts/install.ps1 -Prefix 'C:/local tools/banshee'
```

```sh
CARGO_TARGET_DIR='/tmp/banshee build' sh scripts/install.sh --prefix '/tmp/banshee tools'
```

`SkipBuild` reads Cargo metadata for the selected target directory and looks first
in `<target-directory>/<native-host>/release`, then `<target-directory>/release`.
It checks that the executable runs. It does **not** prove that a reused binary
matches current source; rebuild when source changes. If both layouts exist, the
native-host layout takes precedence. Missing binaries fail with an actionable
error; no remote fallback is attempted.

Existing executables are refused before building unless `-Force` / `--force` is
supplied. Even with force, destination directories, destination links (including
dangling links), and a linked `bin` directory are refused. A complete staged file
is published within the destination directory. Without force, publication also
refuses a destination created during the build. With force, only that executable
is replaced; other files in the prefix are retained. Use a prefix you control.

Installer runtime errors use status 2. PowerShell parameter-binding errors
(unknown parameter or missing value) use status 1. Help returns 0. No installer
changes the user's PATH or shell profile.

## Daily commands

The following commands work in PowerShell and POSIX shells once Banshee is on
PATH. Quotes keep the recipe pipe and the IOC text together.

```text
banshee --help
banshee extract --help
banshee whatis aGVsbG8=
banshee decode base64 aGVsbG8=
banshee recipe 'base64|url' 'aGVsbG8lMjB3b3JsZA==' --raw
banshee extract 'https://example.com 192.0.2.1' --defang
banshee hash calculate hello --algorithm sha256
banshee timestamp to-human 1704067200
```

The decode result is `hello`; the recipe result is `hello world`. Use `--file`
for byte-exact file input, especially with hashes. stdin also works:

```powershell
'aGVsbG8=' | banshee decode base64
```

```sh
printf '%s' 'aGVsbG8=' | banshee decode base64
```

Create a small `sample.txt` containing `hello` before trying this local report and
evidence workflow. Run in a writable directory; outputs must initially be absent.

```text
banshee report sample.txt --format json --output report.json
banshee evidence create sample.txt --output case-evidence
banshee evidence verify case-evidence
banshee diff report.json report.json
```

`--output` avoids shell-specific redirection encodings and refuses replacement by
default. Add `--force` to explicitly replace a supported output. Evidence bundles
omit the source sample unless you supply `--include-sample`. A self-comparison
returns status 0. Compare two distinct reports to identify changes.

CLI statuses: **0** success; **1** findings when `--fail-on-findings` is enabled,
differences from `diff`, or failed evidence integrity; **2** operational/input
error. For example, `banshee --fail-on-findings extract '192.0.2.1'` returns 1.
Check `$LASTEXITCODE` immediately in PowerShell or `$?` in a POSIX shell. IOC
findings are indicators for review, not a malware verdict. `--quiet` suppresses
normal output while retaining errors/status; `--verbose` prints diagnostics to
stderr. Use `--no-color` when plain human-readable output is needed.

## Completions and manual

Generate definitions with `banshee completions bash`, `zsh`, `fish`, `powershell`,
or `elvish`. Review the generated code before adding it to your shell configuration.
For example, generate and load a PowerShell completion file explicitly:

```powershell
banshee completions powershell --output ./banshee-completion.ps1
. ./banshee-completion.ps1
```

```sh
banshee completions bash --output ./banshee-completion.bash
# Load in Bash, after review:
. ./banshee-completion.bash
banshee manpage --output ./banshee.1
man -l ./banshee.1
```

`man -l` requires a compatible Linux man viewer; on macOS use `groff -man -Tascii
./banshee.1` if installed, or the CLI's per-command help. Installers leave generated
completion and manual locations to you.

## Troubleshooting

Start with `banshee doctor` (or `banshee doctor --json`). It runs offline
self-tests for the compression libraries (including liblzma), the decoder and
rule engine, the embedded TLD snapshot, the temporary directory and PATH, and
exits with status 2 when a check fails.

| Symptom | Action |
| --- | --- |
| `cargo`, `rustc` or `pwsh` not found | Install the prerequisite and open a fresh terminal; verify the command resolves before retrying. |
| MSVC linker / Windows SDK missing | Add the C++ desktop workload in Visual Studio Build Tools; use a native Windows Rust host. |
| Linux linker/compiler missing | Install the platform's native build toolchain; on Debian/Ubuntu use `build-essential`. |
| liblzma/XZ build dependency missing | On Debian/Ubuntu install `pkg-config liblzma-dev`; on macOS run `brew install xz pkg-config`. |
| liblzma loader error after moving the binary | Install the matching liblzma runtime on the destination machine; on macOS retain/install Homebrew `xz`. Check the binary's dependencies with `otool -L` or `ldd`. |
| Python 3 missing on Linux/macOS | Install Python 3 and ensure `python3` resolves in the shell. |
| Dependencies cannot be fetched | Check connectivity or prepopulate Cargo's dependency cache. A locked build may still require downloads; installing from source is not inherently offline. |
| PowerShell blocks script execution | Follow your machine's policy; for a trusted reviewed script, use an approved process-scoped policy. Do not change machine-wide policy just to install. |
| Permission denied or executable is in use | Select a writable user prefix; close running Banshee processes before forcing an update on Windows. |
| Destination exists | Verify the path, then use explicit force to update; default refusal preserves it. |
| Destination is a link/directory | Choose a regular destination in a prefix you control; force does not remove those objects. |
| `SkipBuild` cannot find/run a binary | Rebuild without SkipBuild using the same Cargo target-directory settings and native host. |
| Wrong binary/version after installation | Run the installed absolute path, inspect command discovery/PATH order, and rebuild rather than reuse a stale release. |
| Completion/output file exists | Use a fresh path, or explicitly add the CLI's `--force` after reviewing it. |

## Isolated installer checks

CI and local checks can run these entry points from any directory:

```powershell
pwsh -NoProfile -File ./scripts/test-install.ps1
```

```sh
sh scripts/test-install.sh
```

The tests reuse an existing local native release binary, building one only when
none exists, and seed a separate temporary Cargo target directory. They exercise
SkipBuild installation under prefixes containing spaces, relative prefixes,
overwrite refusal and explicit force, missing binaries, help/invalid arguments,
structured output, exit statuses, completions/manual generation and daily examples.
Windows checks exercise a linked `bin` junction; Linux/macOS checks also exercise
symbolic and dangling links. No user prefix or
PATH is changed. Unique test directories and their logs are retained for inspection;
the final output gives the exact path so you can remove it when finished.
