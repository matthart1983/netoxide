# Releasing

How a version goes out. The workflow in `.github/workflows/release.yml` does the building; a person does the deciding.

## Before the first release

These block 0.1.0 and none of them is code:

1. **Choose a licence.** The repository has none, so nobody may use what a release contains. Add `LICENSE`, set `license` in the workspace `Cargo.toml`, and remove `[licenses.private] ignore = true` from `deny.toml`.
2. **Check the name.** "Netoxide" has had no trademark check and sits close to Oxide Computer Company.
3. **Merge the stacked pull requests** into `master`, oldest first.
4. **Decide whether the repository goes public.** It is private today.

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
3. In `CHANGELOG.md`, replace "(not yet released)" with the date, and check the list against `git log` since the last tag.
4. Read `docs/status.md`. Every limit there must still be true, and every new limit must be there.
5. Commit, merge to `master`, then tag that commit and push the tag:

   ```sh
   git tag -a v0.1.0 -m "Netoxide 0.1.0"
   git push origin v0.1.0
   ```

6. The workflow tests, builds and creates a **draft** release with `netoxide-<version>-x86_64-linux.tar.gz` and its SHA-256. Download the archive, check `./oxd --version`, and install it in a VM by `dist/README.md`.
7. Paste the version's section of `CHANGELOG.md` into the draft and publish it.

## What a release contains

`oxd`, `ox` and `netoxide-tui` built for x86-64 Linux against glibc, the systemd unit, the install steps, the example configs and the JSON Schema. The binaries load `libnftables.so.1` at run time, so the `nftables` package must be installed on the box.

The archive is not signed. Signing keys belong to the steward entity, which does not exist yet.

## Not done

- No packages for any distribution, no container image, no OS image.
- No builds for ARM.
- No reproducible-build check.
