uv 0.11.19 (7b2cff1c3 2026-06-03 aarch64-apple-darwin). ALTERNATIVE pair (claim 8): [tool.uv] override-dependencies = ["six==1.16.0"] + sources path entry; six NOT in project.dependencies.
Lock gains [manifest] overrides = [{ name = "six", path = "<relpath>" }]; six [[package]] uses path source; requires-dist untouched.
Installs from vendored wheel; plain sync byte-stable.
