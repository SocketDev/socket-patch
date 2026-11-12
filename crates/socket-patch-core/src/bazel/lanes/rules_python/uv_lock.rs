//! `H-PY3`, `pip.parse(uv_lock = ...)`: the uv pair rewrite. When `uv_lock`
//! is set it decides the bytes and the tag's requirements files are not
//! package locks.
//!
//! Stub until `wp-lane-py-locks` (wave 7) replaces this file.

use crate::bazel::model::{LaneSpec, Mode};

pub const H_PY3: LaneSpec = LaneSpec::stub("H-PY3", Mode::Hosted, &["Y4"]);
