#!/usr/bin/env python3
"""Download and verify the upstream Botan release tarball into vendor/.

Run before `cargo publish -p botan-src`. Reads release.toml so the
version/sha/URL stays in lockstep with what build.rs sees.

Requires Python 3.11+ (for tomllib).
"""

import hashlib
import sys
import tomllib
import urllib.request
from pathlib import Path


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    raw = tomllib.loads((repo / "release.toml").read_text())
    # Expand `{key}` references between fields so e.g. url can refer to {version}.
    info = {k: v.format(**raw) if isinstance(v, str) else v for k, v in raw.items()}
    vendor = repo / "vendor"
    vendor.mkdir(exist_ok=True)
    tarball = vendor / f"Botan-{info['version']}.tar.xz"

    if not tarball.exists():
        print(f"downloading {info['url']}")
        urllib.request.urlretrieve(info["url"], tarball)

    actual = hashlib.sha256(tarball.read_bytes()).hexdigest()
    if actual != info["sha256"]:
        tarball.unlink()
        print(
            f"sha256 mismatch for {tarball.name}: "
            f"expected {info['sha256']}, got {actual}",
            file=sys.stderr,
        )
        return 1
    print(f"ok: {tarball}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
