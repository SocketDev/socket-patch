"""The toy ruleset of the core fixture: a JSON lock in, one `http_file` per package out.

It loads no external ruleset, so a workspace that uses it builds with
nothing but the modules Bazel itself brings. The shape is the one real
rulesets have: a hub repository of aliases (`@toy`) over one spoke
repository per locked package (`@toy_<name>`), each fetched from the lock's
URL under a sha256 that Bazel enforces at fetch.

The lock:

    {
      "lockVersion": 1,
      "packages": {"<name>": {"version": "...", "url": "...", "sha256": "..."}},
      "pinsHash": <int>
    }

`pinsHash` is a derived value, as `__RESOLVED_ARTIFACTS_HASH` is in
`maven_install.json`: Starlark `hash()` of one `<name> <sha256>\\n` line per
package, in name order. A lock whose pins changed without it fails to load,
so whoever rewrites a pin has to rewrite the derived value too.

Three entry points read a lock:

- `toy`, a module extension (Bzlmod). Bazel records the lock file as an
  input of the extension in `MODULE.bazel.lock`.
- `toy_facts`, the same hub from an extension that records nothing but
  facts (Bazel 8.6 and later): one fact per package the toy registry
  serves, none for a package pinned to any other URL.
- `toy_lock`, a repository rule (WORKSPACE). It writes `@<hub>//:repos.bzl`,
  whose `toy_repos()` declares the spokes. A Bzlmod hub carries an empty
  `toy_repos()`, so a WORKSPACE that names the same hub keeps loading in a
  workspace that reads both files, where the Bzlmod hub shadows it.

A package file is a POSIX shell script that prints which bytes it is;
`toy_consumer` makes it runnable for `bazel run` without a shell action.

Every fixture workspace carries the same copy of this file.
"""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")

# A package the toy registry serves is "from the index"; one pinned to any
# other URL is a direct reference and gets no fact.
REGISTRY = "https://registry.toy.invalid/"

def _packages(text):
    lock = json.decode(text)
    if lock.get("lockVersion") != 1:
        fail("toy lock: unsupported lockVersion %r" % lock.get("lockVersion"))
    packages = lock["packages"]
    pins = "".join(["%s %s\n" % (name, packages[name]["sha256"]) for name in sorted(packages)])
    if lock.get("pinsHash") != hash(pins):
        fail("toy lock: pinsHash is %r but the pins hash to %d" % (lock.get("pinsHash"), hash(pins)))
    return packages

def toy_spokes(hub, packages):
    """Declares one `http_file` repository per package of a decoded lock."""
    for name, package in packages.items():
        http_file(
            name = "%s_%s" % (hub, name),
            downloaded_file_path = name + ".sh",
            sha256 = package["sha256"],
            urls = [package["url"]],
        )

def _hub_build(hub, names):
    alias = 'alias(name = "%s", actual = "@%s_%s//file", visibility = ["//visibility:public"])\n'
    return "".join([alias % (name, hub, name) for name in sorted(names)])

def _toy_hub_impl(rctx):
    rctx.file("BUILD.bazel", _hub_build(rctx.attr.hub, rctx.attr.packages))

    # A WORKSPACE that declares a hub of the same name still loads its
    # `repos.bzl`. Where Bzlmod is on, that label is this repository.
    rctx.file("repos.bzl", "def toy_repos():\n    pass\n")

_toy_hub = repository_rule(
    implementation = _toy_hub_impl,
    attrs = {"hub": attr.string(mandatory = True), "packages": attr.string_list()},
)

def _declare(mctx):
    packages = {}
    for module in mctx.modules:
        for tag in module.tags.lock:
            for name, package in _packages(mctx.read(tag.file)).items():
                if name in packages:
                    fail("toy lock: %s is locked twice" % name)
                packages[name] = package
    toy_spokes("toy", packages)
    _toy_hub(name = "toy", hub = "toy", packages = sorted(packages))
    return packages

def _toy_impl(mctx):
    _declare(mctx)

_LOCK_TAG = tag_class(attrs = {"file": attr.label(mandatory = True)})

toy = module_extension(implementation = _toy_impl, tag_classes = {"lock": _LOCK_TAG})

def _toy_facts_impl(mctx):
    packages = _declare(mctx)
    return mctx.extension_metadata(
        reproducible = True,
        facts = {
            name: {"dist": package["url"], "sha256": package["sha256"]}
            for name, package in packages.items()
            if package["url"].startswith(REGISTRY)
        },
    )

toy_facts = module_extension(implementation = _toy_facts_impl, tag_classes = {"lock": _LOCK_TAG})

def _toy_lock_impl(rctx):
    packages = _packages(rctx.read(rctx.attr.lock))
    rctx.file("BUILD.bazel", _hub_build(rctx.name, packages.keys()))
    rctx.file("repos.bzl", """load("@//:toy.bzl", "toy_spokes")

def toy_repos():
    toy_spokes(%r, %r)
""" % (rctx.name, packages))

toy_lock = repository_rule(
    implementation = _toy_lock_impl,
    attrs = {"lock": attr.label(allow_single_file = True, mandatory = True)},
)

def _toy_consumer_impl(ctx):
    out = ctx.actions.declare_file(ctx.label.name + ".sh")
    ctx.actions.expand_template(
        template = ctx.file.src,
        output = out,
        substitutions = {},
        is_executable = True,
    )
    return [DefaultInfo(executable = out)]

toy_consumer = rule(
    implementation = _toy_consumer_impl,
    attrs = {"src": attr.label(allow_single_file = True, mandatory = True)},
    executable = True,
)
