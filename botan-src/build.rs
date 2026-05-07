// Parses release.toml and exposes its values as compile-time `env!`
// strings inside src/lib.rs. The hand-rolled parser handles the
// trivial subset of TOML actually used in release.toml — three
// top-level `key = "value"` lines plus comments — to avoid pulling in
// a TOML build-dependency.
use std::fs;
use std::path::Path;

fn extract(content: &str, key: &str) -> Option<String> {
    for line in content.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once('=') {
            if k.trim() == key {
                return Some(v.trim().trim_matches('"').to_string());
            }
        }
    }
    None
}

fn parse_botan_version(s: &str) -> Option<(u32, u32, u32)> {
    let mut parts = s.split('.').map(|p| p.parse::<u32>().ok());
    Some((parts.next()??, parts.next()??, parts.next()??))
}

// botan-src crate version is `0.MNNPP.X` where M.NN.PP is the bundled
// Botan version. Cross-check that against release.toml so we never
// publish e.g. 0.31100.0 with a Botan 3.11.1 tarball inside.
fn parse_crate_botan_version(crate_version: &str) -> Option<(u32, u32, u32)> {
    let mut parts = crate_version.split('.');
    parts.next()?; // leading "0"
    let encoded: u32 = parts.next()?.parse().ok()?;
    Some((encoded / 10000, (encoded / 100) % 100, encoded % 100))
}

fn main() {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    let manifest_dir = Path::new(&manifest_dir);
    let release_path = manifest_dir.join("release.toml");
    println!("cargo:rerun-if-changed=release.toml");
    let content = fs::read_to_string(&release_path)
        .unwrap_or_else(|e| panic!("read {}: {e}", release_path.display()));

    let pairs = [
        ("version", "BOTAN_VERSION"),
        ("sha256", "BOTAN_TARBALL_SHA256"),
        ("url", "BOTAN_TARBALL_URL"),
    ];
    let mut values = std::collections::HashMap::new();
    for (key, _) in pairs {
        let value =
            extract(&content, key).unwrap_or_else(|| panic!("release.toml missing key `{key}`"));
        values.insert(key, value);
    }
    // Expand `{key}` references between fields (so `url` can refer to `{version}`).
    let raw: Vec<(&str, String)> = values.iter().map(|(k, v)| (*k, v.clone())).collect();
    for v in values.values_mut() {
        for (k, replacement) in &raw {
            *v = v.replace(&format!("{{{k}}}"), replacement);
        }
    }
    for (key, env_var) in pairs {
        println!("cargo:rustc-env={env_var}={}", values[key]);
    }

    let botan_version = parse_botan_version(&values["version"]).unwrap_or_else(|| {
        panic!(
            "release.toml `version` not in M.N.P form: {}",
            values["version"]
        )
    });
    let crate_version = std::env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let crate_encoded = parse_crate_botan_version(&crate_version).unwrap_or_else(|| {
        panic!("can't decode botan version from crate version `{crate_version}`")
    });
    if crate_encoded != botan_version {
        panic!(
            "\nbotan-src crate version `{crate_version}` encodes Botan {}.{}.{},\n\
             but release.toml says Botan {}.{}.{}. Bump one or the other so they agree.\n",
            crate_encoded.0,
            crate_encoded.1,
            crate_encoded.2,
            botan_version.0,
            botan_version.1,
            botan_version.2,
        );
    }

    // Refuse to build (or publish, via the default `cargo publish` verify
    // step) without the upstream tarball staged in vendor/. Catches the
    // "publish with empty vendor/" footgun.
    let tarball = manifest_dir
        .join("vendor")
        .join(format!("Botan-{}.tar.xz", values["version"]));
    println!("cargo:rerun-if-changed={}", tarball.display());
    if !tarball.exists() {
        panic!(
            "\nBotan source tarball missing at {}.\n\
             Run `python3 scripts/fetch.py` from botan-src/ to download it\n\
             before building or publishing this crate.\n",
            tarball.display()
        );
    }
}
