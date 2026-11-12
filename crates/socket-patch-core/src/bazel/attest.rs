//! The consumer verdict for `vex` and `apply --check` (design 7): whether
//! the Bazel build consumes a pin. The lane gate is re-run at discovery, so
//! a pin whose proof no longer holds is withheld.
//!
//! Stub until `wp-attest` (wave 4) replaces this file. Until then
//! `LaneOps::attest` withholds every governed package.
