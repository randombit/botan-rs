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

def compute_features(features, for_who):
    feat = []
    if 'vendored' in features:
        feat.append('vendored')

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

    if len(args) > 2:
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

    KNOWN_FEATURES = ['vendored', 'git', 'no-std']

    features = [] if len(args) == 1 else args[1].split(',')

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

    if 'vendored' in features:
        run_command(['git', 'submodule', 'update', '--init', '--depth', '3'])
    elif 'git' in features:
        nproc = multiprocessing.cpu_count()
        botan_src = 'botan-git'
        run_command(['git', 'clone', '--depth', '1', 'https://github.com/randombit/botan.git', botan_src])

        import tomllib
        excludes = tomllib.loads(open(os.path.join('botan-src', 'Cargo.toml')).read())['package']['exclude']
        for exclude in excludes:
            path = exclude.replace('botan/', botan_src + '/')
            if os.path.isdir(path):
                shutil.rmtree(path)
            elif os.path.isfile(path):
                os.remove(path)

        run_command(['./configure.py',
                     '--compiler-cache=%s' % (options.compiler_cache),
                     '--without-documentation',
                     '--no-install-python-module',
                     '--build-targets=shared',
                     '--disable-modules=%s' % (disabled_modules)], botan_src)
        run_command(['make', '-j', str(nproc)], botan_src)
        run_command(['sudo', 'make', 'install'], botan_src)
    elif os.access(homebrew_dir, os.R_OK):
        # only install homebrew botan if not vendored/git
        run_command(['brew', 'install', 'botan'])
        os.environ["RUSTFLAGS"] = "-D warnings -L/opt/homebrew/lib"
        os.environ["RUSTDOCFLAGS"] = "-D warnings -L/opt/homebrew/lib"
        os.environ["DYLD_LIBRARY_PATH"] = homebrew_dir

    run_command(['rustc', '--version'])

    sys_features = compute_features(features, 'sys')
    lib_features = compute_features(features, 'lib')

    run_command(['cargo', 'build'] + sys_features, 'botan-sys')
    run_command(['cargo', 'test'] + sys_features, 'botan-sys')

    run_command(['cargo', 'build'] + lib_features, 'botan')
    run_command(['cargo', 'test'] + lib_features, 'botan')

    run_command([options.compiler_cache, '--show-stats'])

if __name__ == '__main__':
    sys.exit(main())
