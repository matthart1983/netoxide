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

6. The workflow tests, builds, installs the packages in containers of six distributions, and creates a **draft** release with the archive, the `.deb`, the `.rpm` and one file of SHA-256 sums. Download them, check the sums, and run `dist/package-systemd-test.sh` on the directory: it installs each package in a container that runs systemd.
7. Paste the version's section of `CHANGELOG.md` into the draft and publish it.

## What a release contains

`oxd`, `ox` and `netoxide-tui` built for x86-64 Linux, the systemd unit, the install steps, the example configs and the JSON Schema, as a `.deb`, an `.rpm` and a tar archive. The programs are built in a Debian 11 container, so they need glibc 2.30 or later (`dist/package.sh` reads the number from the programs and puts it in the `.deb`). The daemon runs the `nft` program to load rules, so the `nftables` package must be installed on the box.

Nothing is signed, and there is no package repository to add: a package is downloaded from the release page. Signing keys belong to the steward entity, which does not exist yet.

## Not done

- No apt or dnf repository, no container image, no OS image.
- No builds for ARM.
- No reproducible-build check.
