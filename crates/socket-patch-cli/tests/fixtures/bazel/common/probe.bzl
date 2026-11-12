"""socket_probe: the proof-ladder target every fixture workspace defines.

Each source is symlinked to an output under `<name>.out/` with
`ctx.actions.symlink`: no shell and no toolchain, so one rule builds on
every Bazel line from 5.4.1 on and on Windows without Bash. `bazel query`
over the target's dependencies lists the files Bazel materialised (tier 0);
building it makes each of them an action input whose output has the same
bytes (tier 1).

A tree-artifact input (rules_js `:node_modules/<pkg>/dir`) gets a directory
output: `ctx.actions.symlink` rejects a file output for a directory target.

The test harness copies this file to the workspace root, so a fixture loads
it as `load("//:probe.bzl", "socket_probe")` and must not ship its own.
"""

def _socket_probe_impl(ctx):
    outputs = []
    seen = {}
    for src in ctx.files.srcs:
        if src.basename in seen:
            # Two outputs of one name would make the proof ambiguous.
            fail("socket_probe: {} and {} share a file name; probe them in separate targets".format(
                seen[src.basename],
                src.path,
            ))
        seen[src.basename] = src.path
        name = "{}.out/{}".format(ctx.label.name, src.basename)
        if src.is_directory:
            out = ctx.actions.declare_directory(name)
        else:
            out = ctx.actions.declare_file(name)
        ctx.actions.symlink(output = out, target_file = src)
        outputs.append(out)
    return [DefaultInfo(files = depset(outputs))]

socket_probe = rule(
    implementation = _socket_probe_impl,
    attrs = {
        "srcs": attr.label_list(allow_files = True, mandatory = True),
    },
)
