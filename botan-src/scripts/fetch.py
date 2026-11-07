#!/usr/bin/env python3
"""Produce vendor/Botan-X.Y.Z.tar.xz, the source tarball bundled in this crate.

A full Botan release tarball is ~10 MB compressed, which is the crates.io
upload limit, and two thirds of it is the test suite. The crate therefore
bundles a repack of the upstream release containing only what configure.py
and the library build consume (see KEEP below).

The repack is reproducible from the upstream tarball alone:

  1. The upstream release is downloaded (cached in upstream/) and checked
     against `upstream_sha256` in release.toml.
  2. The entries matching KEEP are copied, in upstream order, as the raw
     tar header and data blocks of the upstream archive. The output tar
     stream is thus a byte subsequence of the upstream tar stream, and does
     not depend on how the running Python serializes tar headers.
  3. The tar stream is xz compressed and written to vendor/.

release.toml pins `vendored_tar_sha256`, the SHA-256 of the *decompressed*
vendored tarball, and build.rs/lib.rs verify that before extracting. Pinning
the tar stream rather than the .xz bytes keeps the pin independent of the
liblzma version used to compress, while still covering every byte that gets
extracted. To audit a published crate:

    xz -dc vendor/Botan-X.Y.Z.tar.xz | sha256sum

Run this before `cargo publish -p botan-src`; CI runs it before every
vendored build. Requires Python 3.11+ (tomllib).
"""

import argparse
import hashlib
import io
import lzma
import sys
import tarfile
import tomllib
import urllib.request
from pathlib import Path

# Paths, relative to the tarball's top-level directory, that end up in the
# vendored tarball. A trailing slash means the whole directory. Everything
# else (src/tests, doc, src/cli, src/fuzzer, src/python, src/scripts, ...)
# is dropped. All of src/lib is kept, so module selection via
# BOTAN_CONFIGURE_* works exactly as with a full source tree.
KEEP = (
    "configure.py",
    "license.txt",
    "news.rst",
    "readme.rst",
    "src/build-data/",
    "src/lib/",
)

BLOCKSIZE = tarfile.BLOCKSIZE


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_release_toml(path: Path) -> dict:
    raw = tomllib.loads(path.read_text())
    # Expand `{key}` references between fields so e.g. url can refer to {version}.
    return {k: v.format(**raw) if isinstance(v, str) else v for k, v in raw.items()}


def keep(rel: str, is_dir: bool) -> bool:
    """Is the entry at `rel` (relative to the top-level dir) part of the repack?"""
    if is_dir and rel == "":
        return True  # the top-level directory itself
    for k in KEEP:
        if k.endswith("/"):
            if (rel + "/").startswith(k):
                return True
        elif rel == k:
            return True
        if is_dir and k.startswith(rel + "/"):
            return True  # an ancestor directory of something we keep
    return False


def repack(upstream_tar: bytes, version: str) -> tuple[bytes, list[tarfile.TarInfo], int]:
    """Return (repacked tar stream, kept upstream members, total upstream members)."""
    top = f"Botan-{version}"
    out = bytearray()
    kept: list[tarfile.TarInfo] = []
    kept_names: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(upstream_tar)) as tf:
        if tf.pax_headers:
            sys.exit("upstream tarball has global pax headers; refusing to repack")
        members = tf.getmembers()
        for m in members:
            first, _, rel = m.name.partition("/")
            parts = m.name.split("/")
            if first != top or ".." in parts or "" in parts[1:]:
                sys.exit(f"unexpected path in upstream tarball: {m.name!r}")
            if not keep(rel, m.isdir()):
                continue
            if m.isdev() or m.isfifo():
                sys.exit(f"unexpected special file in upstream tarball: {m.name!r}")
            if m.islnk() and m.linkname not in kept_names:
                sys.exit(f"{m.name!r} is a hard link to {m.linkname!r}, which is not kept")
            # m.offset is the first header block (including any pax/GNU long name
            # extension blocks that precede the ustar header), m.offset_data the
            # first data block; data is padded to a whole number of blocks.
            end = m.offset_data + ((m.size + BLOCKSIZE - 1) // BLOCKSIZE) * BLOCKSIZE
            out += upstream_tar[m.offset : end]
            kept.append(m)
            kept_names.add(m.name)
    # End-of-archive marker and record padding, as tar(1) and tarfile write them.
    out += b"\0" * (2 * BLOCKSIZE)
    if remainder := len(out) % tarfile.RECORDSIZE:
        out += b"\0" * (tarfile.RECORDSIZE - remainder)
    return bytes(out), kept, len(members)


def verify_repack(upstream_tar: bytes, repacked: bytes, kept: list[tarfile.TarInfo]) -> None:
    """Re-parse the repack and check it holds exactly the kept upstream entries."""
    attrs = ("name", "type", "mode", "uid", "gid", "uname", "gname", "mtime", "size", "linkname")
    with (
        tarfile.open(fileobj=io.BytesIO(upstream_tar)) as old,
        tarfile.open(fileobj=io.BytesIO(repacked)) as new,
    ):
        members = new.getmembers()
        if len(members) != len(kept):
            sys.exit(f"repack has {len(members)} entries, expected {len(kept)}")
        for a, b in zip(kept, members):
            for attr in attrs:
                if getattr(a, attr) != getattr(b, attr):
                    sys.exit(f"repack entry {b.name!r}: {attr} differs from upstream")
            if a.isfile() and old.extractfile(a).read() != new.extractfile(b).read():
                sys.exit(f"repack entry {b.name!r}: contents differ from upstream")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument(
        "--upstream",
        type=Path,
        metavar="TARBALL",
        help="use this already-downloaded upstream tarball instead of upstream/Botan-X.Y.Z.tar.xz",
    )
    args = ap.parse_args()

    crate = Path(__file__).resolve().parent.parent
    release = load_release_toml(crate / "release.toml")
    version = release["version"]
    name = f"Botan-{version}.tar.xz"
    missing: list[str] = []

    # 1. The upstream release tarball.
    downloaded = False
    if args.upstream:
        upstream_path = args.upstream
    else:
        upstream_dir = crate / "upstream"
        upstream_dir.mkdir(exist_ok=True)
        upstream_path = upstream_dir / name
        if not upstream_path.exists():
            print(f"downloading {release['url']}")
            urllib.request.urlretrieve(release["url"], upstream_path)
            downloaded = True
    upstream_xz = upstream_path.read_bytes()
    upstream_sha = sha256_hex(upstream_xz)
    if release.get("upstream_sha256"):
        if upstream_sha != release["upstream_sha256"]:
            if downloaded:
                upstream_path.unlink()
            sys.exit(
                f"sha256 mismatch for {upstream_path}: "
                f"expected {release['upstream_sha256']}, got {upstream_sha}"
            )
    else:
        missing.append(f'upstream_sha256 = "{upstream_sha}"')
    print(f"upstream: {upstream_path} ({len(upstream_xz):,} bytes)")
    print(f"  sha256 {upstream_sha}")

    # 2. Repack.
    upstream_tar = lzma.decompress(upstream_xz)
    repacked, kept, total = repack(upstream_tar, version)
    verify_repack(upstream_tar, repacked, kept)
    tar_sha = sha256_hex(repacked)
    vendored_xz = lzma.compress(
        repacked,
        format=lzma.FORMAT_XZ,
        check=lzma.CHECK_CRC64,
        preset=9 | lzma.PRESET_EXTREME,
    )
    if sha256_hex(lzma.decompress(vendored_xz)) != tar_sha:
        sys.exit("xz round trip failed")

    # 3. Write vendor/, refusing to leave a tarball the build would reject.
    vendor = crate / "vendor"
    vendor.mkdir(exist_ok=True)
    vendored_path = vendor / name
    for stale in vendor.glob("Botan-*.tar.xz"):
        if stale.name != name:
            print(f"removing stale {stale} (Cargo would publish it too)")
            stale.unlink()
    if release.get("vendored_tar_sha256") and tar_sha != release["vendored_tar_sha256"]:
        vendored_path.unlink(missing_ok=True)
        sys.exit(
            f"repacked tar stream sha256 mismatch: expected {release['vendored_tar_sha256']}, "
            f"got {tar_sha} (did the upstream tarball or KEEP change?)"
        )
    vendored_path.write_bytes(vendored_xz)
    print(
        f"vendored: {vendored_path} ({len(vendored_xz):,} bytes): "
        f"kept {len(kept)} of {total} entries, {len(repacked):,} bytes of tar"
    )
    print(f"  tar sha256 {tar_sha}")
    if not release.get("vendored_tar_sha256"):
        missing.append(f'vendored_tar_sha256 = "{tar_sha}"')

    if missing:
        sys.stdout.flush()
        print("\nrelease.toml is missing pins for this release; add:", file=sys.stderr)
        for line in missing:
            print(f"  {line}", file=sys.stderr)
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
