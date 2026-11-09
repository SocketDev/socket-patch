Locks written by real `uv lock` binaries (uv 0.1.45, 0.2.5, 0.2.15, 0.2.16,
0.2.18, 0.2.34) for the `pyproject.toml` beside each, on macOS arm64 with
CPython 3.11 and `UV_NO_CONFIG=1`. The only edit is the editable root's
absolute path, replaced with `file:///project`. They cover the three uv 0.2
`[[distribution]]` grammars and the uv 0.2.23 move of an entry's inline
`dependencies` ahead of its `sdist`; `tests/upstream_restore_golden.rs`
round-trips them through the hosted rewrite and the hosted unwind.
