def _toy_repo_impl(rctx):
    rctx.file("data.txt", rctx.attr.content + "\n")
    rctx.file("BUILD.bazel", 'exports_files(["data.txt"])\n')

toy_repo = repository_rule(implementation = _toy_repo_impl, attrs = {"content": attr.string()})

def _toy_impl(mctx):
    root = mctx.path(Label("//:MODULE.bazel")).dirname
    root.readdir()
    for mod in mctx.modules:
        for tag in mod.tags.from_dir:
            # The directory name is found by listing, as a go.work `use` or a glob would find it.
            for child in root.get_child("third_party").readdir():
                text = mctx.read(child.get_child("dep.lock"))
                for line in text.splitlines():
                    name, _, content = line.partition("=")
                    toy_repo(name = name, content = content)

toy = module_extension(
    implementation = _toy_impl,
    tag_classes = {"from_dir": tag_class(attrs = {})},
)
