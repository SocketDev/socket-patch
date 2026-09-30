//! Optional installed location used for identity and release-variant probes.
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug)]
pub enum PackageSource<'a> {
    Installed(&'a Path),
}

impl<'a> PackageSource<'a> {
    pub fn path(&self) -> &'a Path {
        match self {
            Self::Installed(path) => path,
        }
    }
}

impl<'a> From<&'a Path> for PackageSource<'a> {
    fn from(dir: &'a Path) -> Self {
        Self::Installed(dir)
    }
}

impl<'a> From<&'a PathBuf> for PackageSource<'a> {
    fn from(dir: &'a PathBuf) -> Self {
        Self::Installed(dir.as_path())
    }
}
