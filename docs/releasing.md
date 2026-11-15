# Releasing

How a version goes out. The workflow in `.github/workflows/release.yml` does the building; a person does the deciding.

## Each release

1. Run the full checks on the commit you mean to release:

   ```sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets -- -D warnings
   OX_REQUIRE_KERNEL_TESTS=1 cargo test --workspace
   cargo deny check
   tests/vm/run.sh
   ```

2. Set the version in the workspace `Cargo.toml` and run `cargo build` so `Cargo.lock` follows.
3. In `CHANGELOG.md`, give the new version's section its date, and check the list against `git log` since the last tag.
4. Read `docs/status.md`. Every limit there must still be true, and every new limit must be there.
5. Commit, merge to `master`, then tag that commit and push the tag:

   ```sh
   git tag -a v0.1.0 -m "Netoxide 0.1.0"
   git push origin v0.1.0
   ```

6. The workflow tests, builds and creates a **draft** release with `netoxide-<version>-x86_64-linux.tar.gz` and its SHA-256. Download the archive, check `./oxd --version`, and install it in a VM by `dist/README.md`.
7. Paste the version's section of `CHANGELOG.md` into the draft and publish it.

## What a release contains

`oxd`, `ox` and `netoxide-tui` built for x86-64 Linux against glibc, the systemd unit, the install steps, the example configs and the JSON Schema. The daemon runs the `nft` program to load rules, so the `nftables` package must be installed on the box.

The archive is not signed. Signing keys belong to the steward entity, which does not exist yet.

## Not done

- No packages for any distribution, no container image, no OS image.
- No builds for ARM.
- No reproducible-build check.
