"""`composer install` from a committed lock, as a repository.

No Bazel ruleset builds PHP or takes Composer packages, so a PHP project
under Bazel writes a rule like this one by hand. This one stands for those
rules and is kept as small as they are: the two Composer files of a project
go in, and its `vendor/` tree comes out. Composer and PHP are the machine's
own, from `PATH`.
"""

_BUILD = """\
filegroup(
    name = "vendor",
    srcs = glob(["vendor/**"]),
    visibility = ["//visibility:public"],
)

exports_files(["vendor/autoload.php"])
"""

def _composer_install_impl(rctx):
    composer = rctx.which("composer")
    if not composer:
        fail("no `composer` on PATH")

    # Read, not linked: Bazel then fetches the repository again when one of
    # the two files changes. A rule that takes them with `rctx.symlink` keeps
    # the tree of the old lock on Bazel 8 and 9.
    rctx.file("composer.json", rctx.read(rctx.attr.composer_json))
    rctx.file("composer.lock", rctx.read(rctx.attr.composer_lock))
    install = rctx.execute([
        composer,
        "install",
        "--no-dev",
        "--no-interaction",
        "--no-plugins",
        "--no-progress",
        "--no-scripts",
        "--prefer-dist",
    ])
    if install.return_code != 0:
        fail("composer install failed:\n" + install.stdout + install.stderr)
    rctx.file("BUILD.bazel", _BUILD)

composer_install = repository_rule(
    implementation = _composer_install_impl,
    attrs = {
        "composer_json": attr.label(mandatory = True, allow_single_file = True),
        "composer_lock": attr.label(mandatory = True, allow_single_file = True),
    },
)
