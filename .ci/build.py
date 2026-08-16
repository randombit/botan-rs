#!/usr/bin/env python3

import multiprocessing
import optparse
import os
import shutil
import subprocess
import sys

def run_command(cmdline, cwd = None):
    print("Running '%s'" % (' '.join(cmdline)))
    sys.stdout.flush()
    sys.stderr.flush()
    proc = subprocess.Popen(cmdline, cwd=cwd)

    proc.communicate()

    if proc.returncode != 0:
        print("ERROR: Running %s failed with rc %d" % (cmdline, proc.returncode))
        sys.exit(1)

def apt_package_available(pkg):
    proc = subprocess.run(['apt-cache', 'show', pkg],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return proc.returncode == 0

def apt_botan_packages():
    """
    Returns (dev_pkg, runtime_pkg) for the newest Botan the distribution provides.

    Ubuntu 24.04 ships only Botan 2 (libbotan-2-dev / libbotan-2-19) while
    Ubuntu 26.04 ships only Botan 3 (libbotan-3-dev / libbotan-3-10), so which
    version gets tested is determined by the runner OS.
    """
    for major in [3, 2]:
        dev_pkg = 'libbotan-%d-dev' % (major)
        if not apt_package_available(dev_pkg):
            continue

        # The runtime package is named after the ABI revision (eg
        # libbotan-3-10); find it via the dependencies of the -dev package
        deps = subprocess.check_output(['apt-cache', 'depends', dev_pkg]).decode()
        prefix = 'libbotan-%d-' % (major)
        for line in deps.splitlines():
            line = line.strip()
            if line.startswith('Depends:'):
                dep = line.split(':', 1)[1].strip()
                if dep.startswith(prefix) and dep != dev_pkg:
                    return (dev_pkg, dep)

        print("ERROR: Unable to determine the runtime package for %s" % (dev_pkg))
        sys.exit(1)

    print("ERROR: No libbotan packages are available")
    sys.exit(1)

def compute_features(features, for_who):
    feat = []
    if 'vendored' in features:
        feat.append('vendored')

    if 'dynamic' in features:
        feat.append('dynamic-loading')

    if for_who == 'lib' and 'no-std' not in features:
        feat.append('std')

    feature_flag = []
    if feat != []:
        feature_flag = ['--features', ','.join(feat)]

    if 'no-std' in features:
        feature_flag += ['--no-default-features']

    return feature_flag

def main(args = None):
    if args is None:
        args = sys.argv

    parser = optparse.OptionParser()

    parser.add_option('--compiler-cache', default='ccache',
                      help='Specify the compiler cache to use')

    (options, args) = parser.parse_args(args)

    if len(args) not in [2, 3]:
        print("ERROR: Unexpected extra arguments")
        return 1

    if options.compiler_cache not in ['ccache', 'sccache']:
        print("ERROR: Unknown compiler cache '%s'" % (options.compiler_cache))
        return 1

    if options.compiler_cache == 'ccache':
        if "CCACHE_MAXSIZE" not in os.environ:
            os.environ["CCACHE_MAXSIZE"] = "2G"
    elif options.compiler_cache == 'sccache':
        if "SCCACHE_MAXSIZE" not in os.environ:
            os.environ["SCCACHE_MAXSIZE"] = "2G"

    KNOWN_TOOLCHAINS = ['stable', 'nightly', '1.85.1']
    KNOWN_FEATURES = ['vendored', 'git', 'no-std', 'minimized', 'dynamic']

    toolchain = args[1]

    if toolchain not in KNOWN_TOOLCHAINS:
        print("ERROR: Unknown toolchain %s (need to update .ci/build.py?)" % (toolchain))
        return 1

    features = [] if len(args) < 3 else args[2].split('+')

    for feat in features:
        if feat not in KNOWN_FEATURES:
            print("ERROR: Unknown feature %s" % (feat))
            return 1

    # Disable functionality that is slow to build and that we do not / can not
    # use since it is not available via the C interface:
    disabled_modules = "tls,pkcs11,sodium,filters"

    os.environ["RUSTFLAGS"] = "-D warnings"

    if 'vendored' in features:
        os.environ["BOTAN_CONFIGURE_COMPILER_CACHE"] = options.compiler_cache
        os.environ["BOTAN_CONFIGURE_DISABLE_MODULES"] = disabled_modules

    if 'git' in features:
        os.environ["INSTALL_PREFIX"] = "/usr/local"
        os.environ["LD_LIBRARY_PATH"] = "/usr/local/lib"
        os.environ["DYLD_LIBRARY_PATH"] = "/usr/local/lib"

    homebrew_dir = "/opt/homebrew/lib"

    run_command([options.compiler_cache, '--show-stats'])

    if 'vendored' in features and 'git' in features:
        print("ERROR: Incompatible features vendored and git")
        return 1

    if 'dynamic' in features and 'vendored' in features:
        print("ERROR: Incompatible features dynamic and vendored")
        return 1

    if 'dynamic' in features and 'no-std' in features:
        print("ERROR: Feature dynamic requires std")
        return 1

    if 'minimized' in features and 'git' not in features:
        print("ERROR: Feature minimized requires git")
        return 1

    if 'vendored' in features:
        run_command([sys.executable, './botan-src/scripts/fetch.py'])
    elif 'git' in features:
        nproc = multiprocessing.cpu_count()
        botan_src = 'botan-git'
        run_command(['git', 'clone', '--depth', '1', 'https://github.com/randombit/botan.git', botan_src])

        import tomllib
        cargo_toml = tomllib.loads(open(os.path.join('botan-src', 'Cargo.toml')).read())['package']

        if 'excludes' in cargo_toml:
            for exclude in cargo_toml['excludes']:
                path = exclude.replace('botan/', botan_src + '/')
                if os.path.isdir(path):
                    shutil.rmtree(path)
                elif os.path.isfile(path):
                    os.remove(path)

        configure_args = ['./configure.py',
                          '--compiler-cache=%s' % (options.compiler_cache),
                          '--without-documentation',
                          '--no-install-python-module',
                          '--build-targets=shared']

        if 'minimized' in features:
            # Build with the smallest possible module set that still
            # includes the FFI layer, to verify that the tests correctly
            # skip whatever functionality is not available
            configure_args += ['--minimized-build', '--enable-modules=ffi']
        else:
            configure_args += ['--disable-modules=%s' % (disabled_modules)]

        run_command(configure_args, botan_src)
        run_command(['make', '-j', str(nproc)], botan_src)
        run_command(['sudo', 'make', 'install'], botan_src)
        os.environ["RUSTFLAGS"] = "-D warnings -L/usr/local/lib"
        os.environ["RUSTDOCFLAGS"] = "-D warnings -L/usr/local/lib"
    elif os.access(homebrew_dir, os.R_OK):
        # only install homebrew botan if not vendored/git
        run_command(['brew', 'install', 'botan'])
        os.environ["RUSTFLAGS"] = "-D warnings -L/opt/homebrew/lib"
        os.environ["RUSTDOCFLAGS"] = "-D warnings -L/opt/homebrew/lib"
        os.environ["DYLD_LIBRARY_PATH"] = homebrew_dir
    elif os.access('/usr/bin/apt-get', os.R_OK):
        (dev_pkg, runtime_pkg) = apt_botan_packages()
        if 'dynamic' in features:
            # With dynamic loading no headers are needed to build, and the
            # library is located at runtime; install only the runtime package
            # to verify this
            run_command(['sudo', 'apt-get', 'install', runtime_pkg])
        else:
            run_command(['sudo', 'apt-get', 'install', dev_pkg])

    run_command(['rustc', '--version'])

    sys_features = compute_features(features, 'sys')
    lib_features = compute_features(features, 'lib')

    # The doctest examples assume a full build, so run only the test
    # binaries (which skip unavailable functionality) against a minimized
    # library
    test_args = ['--tests'] if 'minimized' in features else []

    run_command(['cargo', 'build'] + sys_features, 'botan-sys')
    run_command(['cargo', 'test'] + test_args + sys_features, 'botan-sys')

    run_command(['cargo', 'build'] + lib_features, 'botan')
    run_command(['cargo', 'test'] + test_args + lib_features, 'botan')

    run_command([options.compiler_cache, '--show-stats'])

if __name__ == '__main__':
    sys.exit(main())
