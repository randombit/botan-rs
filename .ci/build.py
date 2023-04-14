#!/usr/bin/env python3

import subprocess
import sys
import os
import multiprocessing

def run_command(cmdline, cwd = None):
    print("Running '%s'" % (' '.join(cmdline)))
    sys.stdout.flush()
    sys.stderr.flush()
    proc = subprocess.Popen(cmdline, cwd=cwd)

    proc.communicate()

    if proc.returncode != 0:
        print("ERROR: Running %s failed with rc %d" % (cmdline, proc.returncode))
        sys.exit(1)

def main(args = None):
    if args is None:
        args = sys.argv

    if len(args) > 2:
        print("ERROR: Unexpected extra arguments")
        return 1

    KNOWN_FEATURES = ['vendored', 'git', 'no-std', 'botan3']

    features = [] if len(args) == 1 else args[1].split(',')

    for feat in features:
        if feat not in KNOWN_FEATURES:
            print("ERROR: Unknown feature %s" % (feat))
            return 1

    if "CCACHE_MAXSIZE" not in os.environ:
        os.environ["CCACHE_MAXSIZE"] = "2G"

    # Disable functionality that is slow to build and that we do not / can not
    # use since it is not available via the C interface:
    disabled_modules = "tls,pkcs11,sodium,filters"

    os.environ["RUSTFLAGS"] = "-D warnings"

    if 'vendored' in features:
        os.environ["BOTAN_CONFIGURE_COMPILER_CACHE"] = "ccache"
        os.environ["BOTAN_CONFIGURE_DISABLE_MODULES"] = disabled_modules

    if 'git' in features:
        os.environ["INSTALL_PREFIX"] = "/usr/local"
        os.environ["LD_LIBRARY_PATH"] = "/usr/local/lib"
        os.environ["DYLD_LIBRARY_PATH"] = "/usr/local/lib"

    run_command(['ccache', '--show-stats'])

    if 'vendored' in features and 'git' in features:
        print("ERROR: Incompatible features vendored and git")
        return 1

    if 'vendored' in features:
        run_command(['git', 'submodule', 'update', '--init', '--depth', '3'])

    if 'git' in features:
        nproc = multiprocessing.cpu_count()
        botan_src = 'botan-git'
        run_command(['git', 'clone', '--depth', '1', 'https://github.com/randombit/botan.git', botan_src])
        run_command(['./configure.py',
                     '--compiler-cache=ccache',
                     '--without-documentation',
                     '--build-targets=shared',
                     '--disable-modules=%s' % (disabled_modules)], botan_src)
        run_command(['make', '-j', str(nproc)], botan_src)
        run_command(['sudo', 'make', 'install'], botan_src)

    run_command(['rustc', '--version'])

    def compute_features(features):
        sys = []
        lib = []

        if 'vendored' in features:
            sys.append('vendored')
            lib.append('vendored')

        if 'no-std' in features:
            # sys is always no_std
            lib.append('no-std')

        if 'git' in features or 'botan3' in features:
            sys.append('botan3')
            lib.append('botan3')

        if sys != []:
            feat = ','.join(sys)
            sys = ['--features', feat]

        if lib != []:
            feat = ','.join(lib)
            lib = ['--features', feat]

        return (sys, lib)

    (sys_features, lib_features) = compute_features(features)

    run_command(['cargo', 'build'] + sys_features, 'botan-sys')
    run_command(['cargo', 'test'] + sys_features, 'botan-sys')

    run_command(['cargo', 'build'] + lib_features, 'botan')
    run_command(['cargo', 'test'] + lib_features, 'botan')

    run_command(['ccache', '--show-stats'])

if __name__ == '__main__':
    sys.exit(main())
