"""Toy module extension for the lockfile probes: one repo per `name=content` line."""

def _toy_repo_impl(rctx):
    rctx.file("data.txt", rctx.attr.content + "\n")
    rctx.file("BUILD.bazel", 'exports_files(["data.txt"])\n')
    for p in rctx.attr.patches:
        rctx.patch(p, strip = 1)

toy_repo = repository_rule(
    implementation = _toy_repo_impl,
    attrs = {
        "content": attr.string(),
        "patches": attr.label_list(),
    },
)

def _parse(text):
    out = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        name, _, content = line.partition("=")
        out[name] = content
    return out

def _toy_impl(mctx):
    patches = {}
    for mod in mctx.modules:
        for tag in mod.tags.override:
            patches.setdefault(tag.repo, []).extend(tag.patches)
            pass
    facts = {}
    for mod in mctx.modules:
        for tag in mod.tags.from_file:
            for name, content in _parse(mctx.read(tag.lock)).items():
                if not content.startswith("direct:"):
                    facts[name + "@index"] = {"dist": content}
                toy_repo(name = name, content = content, patches = patches.get(name, []))
    return None

toy = module_extension(
    implementation = _toy_impl,
    tag_classes = {
        "from_file": tag_class(attrs = {"lock": attr.label(mandatory = True)}),
        "override": tag_class(attrs = {"repo": attr.string(), "patches": attr.label_list()}),
    },
    
)
