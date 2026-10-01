//! Golden snapshots of the randomized equivalence sweeps.
//!
//! #257 moved the crawlers onto the blocking pool and made the hosted
//! rewriters single-pass, and kept each previous implementation as a
//! test-only oracle that the new one had to match on thousands of generated
//! inputs. The oracles are gone; what they proved is kept here instead. Each
//! sweep still generates the same inputs from the same seeds, and its golden
//! file pins, per case, a digest of the input and a digest of the output the
//! oracle and the production code agreed on when the file was blessed. A
//! changed output digest is a behavior change on that case; a changed input
//! digest means the generator itself drifted.
//!
//! Bless only for an intended behavior change:
//! `SOCKET_PATCH_BLESS_GOLDEN=1 cargo test -p socket-patch-core <test>`
//! rewrites the file (review its diff like any other golden).

use std::fmt::Write as _;
use std::path::PathBuf;

use serde::Serialize;
use sha2::{Digest as _, Sha256};

/// One sweep's recorded cases, compared against (or blessed into)
/// `tests/equivalence/<name>.golden` by [`Golden::finish`].
pub(crate) struct Golden {
    name: &'static str,
    about: &'static str,
    lines: Vec<String>,
    /// Cases folded into one line, so a 20k-case sweep stays a small file.
    chunk: usize,
    cases: usize,
    pending: Vec<(String, String)>,
}

/// A short stable digest of `value`'s JSON encoding.
pub(crate) fn digest<T: Serialize + ?Sized>(value: &T) -> String {
    let json = serde_json::to_vec(value).expect("golden values serialize");
    let hash = Sha256::digest(&json);
    hash[..8].iter().fold(String::new(), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

thread_local! {
    static ACTIVE: std::cell::RefCell<Option<Golden>> = const { std::cell::RefCell::new(None) };
}

/// A [`Golden`] the sweep's shared helpers record into through [`record`],
/// for the length of one test.
pub(crate) struct Sweep;

impl Sweep {
    pub(crate) fn start(name: &'static str, about: &'static str) -> Self {
        Self::with(Golden::new(name, about))
    }

    pub(crate) fn with(golden: Golden) -> Self {
        ACTIVE.with(|a| *a.borrow_mut() = Some(golden));
        Sweep
    }

    pub(crate) fn finish(self) {
        let golden = ACTIVE
            .with(|a| a.borrow_mut().take())
            .expect("sweep started");
        golden.finish();
    }
}

impl Drop for Sweep {
    fn drop(&mut self) {
        ACTIVE.with(|a| a.borrow_mut().take());
    }
}

/// Record one case into the running [`Sweep`], if any.
pub(crate) fn record<I, O>(input: &I, output: &O)
where
    I: Serialize + ?Sized,
    O: Serialize + ?Sized,
{
    ACTIVE.with(|a| {
        if let Some(golden) = a.borrow_mut().as_mut() {
            golden.next(input, output);
        }
    });
}

impl Golden {
    /// `about` becomes the file's header: what one case is.
    pub(crate) fn new(name: &'static str, about: &'static str) -> Self {
        Self {
            name,
            about,
            lines: Vec::new(),
            chunk: 1,
            cases: 0,
            pending: Vec::new(),
        }
    }

    /// Fold every `chunk` consecutive cases into one golden line.
    pub(crate) fn chunked(mut self, chunk: usize) -> Self {
        self.chunk = chunk.max(1);
        self
    }

    /// Record one case under `key` (unique within the sweep).
    pub(crate) fn case<I, O>(&mut self, key: impl std::fmt::Display, input: &I, output: &O)
    where
        I: Serialize + ?Sized,
        O: Serialize + ?Sized,
    {
        self.cases += 1;
        if self.chunk == 1 {
            let key = key.to_string().replace(char::is_whitespace, "_");
            self.lines
                .push(format!("{key} {} {}", digest(input), digest(output)));
            return;
        }
        self.pending.push((digest(input), digest(output)));
        if self.pending.len() == self.chunk {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.pending.is_empty() {
            return;
        }
        let first = self.cases - self.pending.len();
        let (inputs, outputs): (Vec<_>, Vec<_>) =
            std::mem::take(&mut self.pending).into_iter().unzip();
        self.lines.push(format!(
            "{first}-{} {} {}",
            self.cases - 1,
            digest(&inputs),
            digest(&outputs)
        ));
    }

    /// [`Golden::case`] keyed by its position in the sweep.
    pub(crate) fn next<I, O>(&mut self, input: &I, output: &O)
    where
        I: Serialize + ?Sized,
        O: Serialize + ?Sized,
    {
        self.case(self.cases, input, output);
    }

    fn path(&self) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/equivalence")
            .join(format!("{}.golden", self.name))
    }

    /// Compare every recorded case with the golden file, naming the first
    /// that differs, or rewrite the file under `SOCKET_PATCH_BLESS_GOLDEN`.
    pub(crate) fn finish(mut self) {
        self.flush();
        let path = self.path();
        if std::env::var_os("SOCKET_PATCH_BLESS_GOLDEN").is_some() {
            let mut text = String::new();
            for line in self.about.lines() {
                let _ = writeln!(text, "# {line}");
            }
            text.push_str("# <case> <input digest> <output digest>\n");
            for line in &self.lines {
                text.push_str(line);
                text.push('\n');
            }
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(&path, text).unwrap();
            return;
        }
        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
        let want: Vec<&str> = text
            .lines()
            .map(|l| l.trim_end_matches('\r'))
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .collect();
        for (got, want) in self.lines.iter().zip(&want) {
            let (got_key, got_rest) = got.split_once(' ').unwrap();
            let (want_key, want_rest) = want.split_once(' ').unwrap_or((want, ""));
            assert_eq!(got_key, want_key, "{}: case order changed", self.name);
            if got_rest != want_rest {
                let (got_in, got_out) = got_rest.split_once(' ').unwrap();
                let (want_in, want_out) = want_rest.split_once(' ').unwrap_or((want_rest, ""));
                assert_eq!(
                    got_in, want_in,
                    "{}: case {got_key}: the generated input changed (generator drift)",
                    self.name
                );
                assert_eq!(
                    got_out, want_out,
                    "{}: case {got_key}: output differs from the blessed oracle output",
                    self.name
                );
            }
        }
        assert_eq!(
            self.lines.len(),
            want.len(),
            "{}: case count changed",
            self.name
        );
    }
}
