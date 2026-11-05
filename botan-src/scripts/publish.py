#!/usr/bin/env python3
"""Publish botan-src to crates.io after checking that the only uncommitted
content going into the crate is the vendored tarball.

The vendored tarball is deliberately not committed to git, so `cargo publish`
has to run with --allow-dirty. That flag switches off cargo's own safety net,
which this script replaces with stricter checks:

  * every tracked file in botan-src/ is unmodified, and HEAD is on a remote
    branch (the commit recorded in .cargo_vcs_info.json should be public)
  * the crate version, release.toml and botan-sys's dependency pin agree, and
    the version is not already on crates.io
  * vendor/ holds exactly the tarball for release.toml's version, regenerated
    by fetch.py and therefore matching the pinned hashes
  * the files cargo would package are exactly the tracked files, that one
    tarball, and the files cargo generates itself
  * the .crate is under the crates.io upload limit

If every check passes it shows a summary, asks for confirmation (unless --yes)
and runs `cargo publish -p botan-src --allow-dirty`. With --dry-run the checks
are identical and cargo publish also gets --dry-run: it packages and runs the
verification build but uploads nothing. Arguments after `--` are passed on to
cargo publish (e.g. `-- --registry foo`).
"""

import argparse
import json
import subprocess
import sys
import tomllib
import urllib.request
from pathlib import Path

CRATE_NAME = "botan-src"
CRATE = Path(__file__).resolve().parent.parent
REPO = CRATE.parent
CRATE_REL = CRATE.relative_to(REPO).as_posix()
UPLOAD_LIMIT = 10 * 1024 * 1024  # crates.io default max_upload_size
# Files cargo adds to every .crate on its own.
CARGO_GENERATED = {"Cargo.toml.orig", "Cargo.lock", ".cargo_vcs_info.json"}


def run(cmd: list[str], cwd: Path = REPO) -> str:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True).stdout


def git(*args: str) -> str:
    return run(["git", *args]).strip()


class Report:
    def __init__(self) -> None:
        self.errors: list[str] = []
        self.warnings: list[str] = []

    def section(self, title: str) -> None:
        print(f"\n{title}")

    def ok(self, msg: str) -> None:
        print(f"  ok    {msg}")

    def info(self, msg: str) -> None:
        print(f"  info  {msg}")

    def warn(self, msg: str) -> None:
        print(f"  WARN  {msg}")
        self.warnings.append(msg)

    def fail(self, msg: str) -> None:
        print(f"  FAIL  {msg}")
        self.errors.append(msg)


def indented(items, limit: int = 20) -> str:
    items = list(items)
    shown = "".join(f"\n          {i}" for i in items[:limit])
    if len(items) > limit:
        shown += f"\n          ... and {len(items) - limit} more"
    return shown


def check_git_state(r: Report) -> str:
    r.section(f"git state of {CRATE_REL}/")
    # Not via git(): its strip() would eat the leading space of the first "XY path" line.
    status = run(["git", "status", "--porcelain", "--", CRATE_REL]).splitlines()
    modified = [line[3:] for line in status if not line.startswith("??")]
    untracked = [line[3:] for line in status if line.startswith("??")]
    if modified:
        r.fail("uncommitted changes to tracked files:" + indented(modified))
    else:
        r.ok("tracked files match HEAD")
    if untracked:
        r.warn("untracked files (not packaged, but tidy up or add them):" + indented(untracked))

    head = git("rev-parse", "HEAD")
    branches = [b.strip() for b in git("branch", "-r", "--contains", head).splitlines()]
    if branches:
        r.ok(f"HEAD {head[:12]} is on {', '.join(branches)}")
    else:
        r.warn(
            f"HEAD {head[:12]} is not on any remote branch; push first so that "
            ".cargo_vcs_info.json points at a public commit"
        )
    return head


def semver_caret_ok(requirement: str, version: str) -> bool:
    """Does `version` satisfy the caret requirement `requirement` (cargo's default)?"""
    req = [int(p) for p in requirement.lstrip("^").split(".")]
    ver = [int(p) for p in version.split(".")]
    req += [0] * (3 - len(req))
    # Caret: the leftmost non-zero component must match; the rest may be >=.
    pivot = next((i for i, p in enumerate(req) if p != 0), len(req) - 1)
    return ver[: pivot + 1] == req[: pivot + 1] and ver >= req


def check_versions(r: Report) -> tuple[str, str]:
    r.section("versions")
    version = tomllib.loads((CRATE / "Cargo.toml").read_text())["package"]["version"]
    release = tomllib.loads((CRATE / "release.toml").read_text())
    botan_version = release["version"]

    major, minor, patch = (int(p) for p in botan_version.split("."))
    encoded = f"0.{major}{minor:02d}{patch:02d}"
    if version.rsplit(".", 1)[0] == encoded:
        r.ok(f"{CRATE_NAME} {version} encodes Botan {botan_version}")
    else:
        r.fail(f"{CRATE_NAME} {version} does not encode Botan {botan_version} (expected {encoded}.X)")

    sys_toml = tomllib.loads((REPO / "botan-sys" / "Cargo.toml").read_text())
    dep = None
    for table in ("build-dependencies", "dependencies"):
        dep = sys_toml.get(table, {}).get(CRATE_NAME)
        if dep:
            break
    requirement = dep["version"] if isinstance(dep, dict) else dep
    if requirement is None:
        r.warn(f"botan-sys/Cargo.toml has no {CRATE_NAME} dependency")
    elif semver_caret_ok(requirement, version):
        r.ok(f"botan-sys requires {CRATE_NAME} {requirement}, satisfied by {version}")
    else:
        r.fail(f"botan-sys/Cargo.toml requires {CRATE_NAME} {requirement}, not satisfied by {version}")

    url = f"https://crates.io/api/v1/crates/{CRATE_NAME}/versions"
    request = urllib.request.Request(
        url, headers={"User-Agent": f"{CRATE_NAME} publish.py (https://github.com/randombit/botan-rs)"}
    )
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            published = {v["num"] for v in json.load(response)["versions"]}
    except Exception as e:  # network trouble is not a reason to block
        r.warn(f"could not query crates.io for published versions: {e}")
    else:
        if version in published:
            r.fail(f"{CRATE_NAME} {version} is already on crates.io")
        else:
            r.ok(f"{CRATE_NAME} {version} is not yet on crates.io")
    return version, botan_version


def check_vendor(r: Report, botan_version: str) -> str:
    r.section("vendored tarball")
    fetch = subprocess.run(
        [sys.executable, "-I", str(CRATE / "scripts" / "fetch.py")],
        cwd=CRATE,
        capture_output=True,
        text=True,
    )
    for line in (fetch.stdout + fetch.stderr).splitlines():
        print(f"        | {line}")
    if fetch.returncode != 0:
        r.fail("fetch.py failed")
    else:
        r.ok("fetch.py regenerated and verified the vendored tarball")

    tarball_rel = f"vendor/Botan-{botan_version}.tar.xz"
    tarballs = sorted(p.name for p in (CRATE / "vendor").glob("Botan-*.tar.xz"))
    if tarballs == [f"Botan-{botan_version}.tar.xz"]:
        r.ok(f"vendor/ contains exactly {tarball_rel}")
    else:
        r.fail(f"vendor/ should contain exactly Botan-{botan_version}.tar.xz, has:" + indented(tarballs))
    return tarball_rel


def check_package_contents(r: Report, tarball_rel: str) -> None:
    r.section("files cargo would package")
    listing = run(["cargo", "package", "-p", CRATE_NAME, "--list", "--allow-dirty"]).split()
    packaged = set(listing)
    prefix = CRATE_REL + "/"
    tracked = {
        line[len(prefix) :]
        for line in git("ls-files", "--", CRATE_REL).splitlines()
        if line.startswith(prefix)
    }
    allowed = tracked | CARGO_GENERATED | {tarball_rel}

    extra = sorted(packaged - allowed)
    if extra:
        r.fail("would publish files that are neither committed nor the vendored tarball:" + indented(extra))
    else:
        r.ok("every packaged file is committed, cargo generated, or the vendored tarball")

    if tarball_rel in packaged:
        r.ok(f"{tarball_rel} is packaged")
    else:
        r.fail(f"{tarball_rel} is not in the package")

    unpackaged = sorted(tracked - packaged)
    if unpackaged:
        r.info(f"{len(unpackaged)} tracked files are not packaged (Cargo.toml `include`):" + indented(unpackaged))


def check_crate_size(r: Report, version: str) -> None:
    r.section("crate size")
    run(["cargo", "package", "-p", CRATE_NAME, "--no-verify", "--allow-dirty"])
    metadata = json.loads(run(["cargo", "metadata", "--no-deps", "--format-version", "1"]))
    crate_file = Path(metadata["target_directory"]) / "package" / f"{CRATE_NAME}-{version}.crate"
    size = crate_file.stat().st_size
    percent = 100 * size / UPLOAD_LIMIT
    if size >= UPLOAD_LIMIT:
        r.fail(f"{crate_file.name} is {size:,} bytes, over the {UPLOAD_LIMIT:,} byte crates.io limit")
    else:
        r.ok(f"{crate_file.name} is {size:,} bytes ({percent:.0f}% of the crates.io limit)")


def main() -> int:
    # Keep our progress lines ordered with the output of the subprocesses we run.
    sys.stdout.reconfigure(line_buffering=True)
    ap = argparse.ArgumentParser(
        description=__doc__.split("\n\n")[0],
        epilog="Arguments after `--` are passed to cargo publish.",
    )
    ap.add_argument("--dry-run", action="store_true", help="run the checks, then `cargo publish --dry-run`")
    ap.add_argument("--yes", "-y", action="store_true", help="do not ask for confirmation")
    ap.add_argument("cargo_args", nargs=argparse.REMAINDER, help=argparse.SUPPRESS)
    args = ap.parse_args()
    cargo_args = args.cargo_args[1:] if args.cargo_args[:1] == ["--"] else args.cargo_args

    r = Report()
    head = check_git_state(r)
    version, botan_version = check_versions(r)
    tarball_rel = check_vendor(r, botan_version)
    check_package_contents(r, tarball_rel)
    check_crate_size(r, version)

    print()
    if r.errors:
        print(f"Not publishing: {len(r.errors)} check(s) failed.")
        return 1

    what = f"{CRATE_NAME} {version} (Botan {botan_version}) from commit {head[:12]}"
    print(f"Ready to publish {what}{' [dry run]' if args.dry_run else ''}.")
    if r.warnings:
        print(f"{len(r.warnings)} warning(s) above.")
    if not args.yes:
        if not sys.stdin.isatty():
            print("No terminal to confirm on; pass --yes to proceed without a prompt.")
            return 1
        if input("Proceed? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Aborted.")
            return 1

    cmd = ["cargo", "publish", "-p", CRATE_NAME, "--allow-dirty"]
    if args.dry_run:
        cmd.append("--dry-run")
    cmd += cargo_args
    print("+", " ".join(cmd))
    return subprocess.run(cmd, cwd=REPO).returncode


if __name__ == "__main__":
    sys.exit(main())
