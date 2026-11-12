"""X4 probe: a non-reproducible extension that reads each tagged file with module_ctx.read."""

def _data_repo_impl(rctx):
    rctx.file("out.txt", rctx.attr.content + "\n")
    rctx.file("BUILD.bazel", 'exports_files(["out.txt"])\n')

_data_repo = repository_rule(
    implementation = _data_repo_impl,
    attrs = {"content": attr.string()},
)

def _x4_impl(mctx):
    count = 0
    size = 0
    for mod in mctx.modules:
        for tag in mod.tags.inputs:
            for f in tag.files:
                size += len(mctx.read(f))
                count += 1
    _data_repo(name = "x4_data", content = "%d files, %d bytes" % (count, size))

x4 = module_extension(
    implementation = _x4_impl,
    tag_classes = {"inputs": tag_class(attrs = {"files": attr.label_list(allow_files = True)})},
)
