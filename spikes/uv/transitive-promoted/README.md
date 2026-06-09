uv 0.11.19 (7b2cff1c3 2026-06-03 aarch64-apple-darwin). AFTER pair: six promoted to [project] dependencies ("six==1.16.0") + [tool.uv.sources] path entry.
Root dependencies = [{ name = "python-dateutil" }, { name = "six" }]; requires-dist = [{ name = "python-dateutil", specifier = "==2.8.2" }, { name = "six", path = "<relpath>" }].
six pinned 1.17.0 -> 1.16.0, path source. uv sync --locked installs from vendored wheel; plain sync byte-stable.
