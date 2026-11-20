# hostcensus

Takes a census of one host: what runs on it and which logs it produces. It runs
once, offline, and writes a single bundle file that a person can read before
they hand it to anyone.

## What must stay true

- **No network connection.** No HTTP client, TLS stack or Kubernetes API client
  in the dependency tree (`deny.toml`), no TCP or UDP sockets in the code
  (`clippy.toml`). Local Unix sockets and Windows named pipes are allowed.
- **No log message.** Files are listed from directory metadata. The tool never
  opens a log file to read it, and it asks the journal only for the unit name
  and time of each entry.
- **Nothing written but the bundle.** No state directory, no identifiers
  persisted on the host.
- **No self-elevation.** It runs with the privileges it is given and says what
  it could not see.
- **Everything it touches is listed in `DATA.md`.** Change both together.
- **One file with `unsafe`.** `src/scanners/event_log_api.rs` calls the
  Windows Event Log API. The crate denies `unsafe` everywhere else.

## Rules shared with the LogPacer collector

hostcensus and the collector that LogPacer runs on a host identify what they
find by the same rules on purpose, so that a container has the same
identifiers in a census and in LogPacer. The two code bases share no crate and
there will not be one. When a scanner fix matters to both, make it in each by
hand.

## Commands

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test --all
cargo deny --locked check advisories bans licenses sources
scripts/third-party-licenses check   # after a dependency change: write
```
