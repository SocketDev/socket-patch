"""A Java runtime toolchain with no Java behind it."""

def _no_java_runtime_impl(_ctx):
    return [platform_common.ToolchainInfo()]

no_java_runtime = rule(implementation = _no_java_runtime_impl)
