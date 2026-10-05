# Changelog

All notable changes to socket-patch are documented here.

## [Unreleased]

v5 centers the workflow on `scan`, `vex` and `vendor`.

### Breaking changes

- `scan` and `get` default to hosted mode (#277).
- `setup` and its publishing helpers are removed (#231).

### Added

- Vendored Maven reactors and Gradle builds, with committed
  repositories and reversible wiring (#500).

### Fixed

- Bound patch API connects and stalled reads (#581).
- Stop npm oracle trees symlinking into a cycle (#582).

  The cycle only appeared with nested workspaces.

## [4.0.0] — 2026-08-20

### Added

- `get --mode hosted` and `get --mode vendored` (#226).

## [3.2.0] — 2026-05-29

- Filesystem safety fixes.
