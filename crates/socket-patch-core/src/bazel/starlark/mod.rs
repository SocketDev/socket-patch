//! The Starlark reader (design 2.1, 2.2): hand-written and bounded like the
//! Gradle script graph. It reads committed files only; nothing evaluates
//! Starlark, so every answer is either what the text says outright or a
//! statement of what could not be read.
//!
//! - [`lexer`] turns bytes into tokens with byte spans and refuses what
//!   Bazel refuses.
//! - [`stmt`] reads the top-level statements and answers queries about a
//!   name as [`Answer::Exact`] or [`Answer::Incomplete`].
//! - [`edit`] holds the one edit, a splice inside a string literal.
//!
//! `MODULE.bazel`, its included segments, the `WORKSPACE` family, `.bzl`
//! macro files and `BUILD` files all go through [`read`]; a [`Dialect`]
//! says which one it is.

pub mod edit;
pub mod lexer;
pub mod stmt;

pub use edit::{replace_string_inner, EditError};
pub use lexer::{Comment, Eol, Span, Unreadable, UnreadableKind};
pub use stmt::{
    read, Answer, Arg, ArgKind, Binding, BindingKind, Call, Dialect, File, Include, Load,
    LoadSymbol, Lookup, OpaqueKind, Reason, Stmt, StmtKind, Uses, Value, ValueKind, Why,
};

/// How deep the readers built on this one follow a chain of files (an
/// `include()` closure, a WORKSPACE macro), and how deep this reader
/// follows brackets inside a value and `def` inside `def`. Past it a
/// value is [`ValueKind::Dynamic`] and a `def` is opaque.
pub const MAX_DEPTH: usize = 8;

/// How many files one workspace model reads.
pub const MAX_FILES: usize = 512;

/// The largest Starlark file that is read; a larger one is refused.
pub const MAX_FILE_BYTES: usize = 1 << 20;

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};
    use std::fmt::Write as _;
    use std::path::{Path, PathBuf};

    use super::lexer::Tok;
    use super::*;
    use crate::test_rng::Rng;

    fn fixtures() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bazel/starlark")
    }

    fn lossy(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// Compare with a committed golden, or write it when blessing. The
    /// fixture directory is `-text`, so a checkout never changes a byte.
    fn golden(path: &Path, got: &str) {
        if std::env::var_os("SOCKET_PATCH_BLESS_GOLDEN").is_some() {
            std::fs::write(path, got).unwrap();
        }
        let want = std::fs::read_to_string(path).unwrap_or_default();
        assert!(
            got == want,
            "{} differs; bless an intended change with SOCKET_PATCH_BLESS_GOLDEN=1\n{got}",
            path.display()
        );
    }

    /// The statement model as text: one line per statement with its line
    /// number, comments as they attach. A string is quoted, a folded
    /// string is `+"..."`, a name is `$name` and anything computed is its
    /// source in `<...>`.
    pub(super) fn render(file: &File<'_>) -> String {
        let mut out = String::new();
        render_block(file, &file.stmts, 0, &mut out);
        out
    }

    fn render_block(file: &File<'_>, stmts: &[Stmt], depth: usize, out: &mut String) {
        let pad = "  ".repeat(depth);
        for stmt in stmts {
            for comment in &stmt.leading {
                let _ = writeln!(out, "{pad}{}", lossy(file.bytes(*comment)));
            }
            let text = match &stmt.kind {
                StmtKind::Call(call) => format!("call {}", render_call(file, call)),
                StmtKind::Bind { name, call, .. } => {
                    format!("bind {name} = {}", render_call(file, call))
                }
                StmtKind::TagCall { proxy, call, .. } => {
                    format!("tag {proxy}.{}", render_call(file, call))
                }
                StmtKind::ConstBind { name, value, .. } => {
                    format!("const {name} = {}", render_value(file, value))
                }
                StmtKind::Include(include) => match (&include.label, include.exact()) {
                    (Some(label), Some((_, dev))) => format!("include {label:?} dev={dev}"),
                    _ => format!("include ? {}", render_call(file, &include.call)),
                },
                StmtKind::Load(load) => {
                    let symbol = |s: &LoadSymbol| match s.local == s.name {
                        true => format!(" {}", s.name),
                        false => format!(" {}={}", s.local, s.name),
                    };
                    let symbols: String = load.symbols.iter().map(symbol).collect();
                    format!("load {:?}{symbols}", load.module)
                }
                StmtKind::Docstring => "docstring".to_string(),
                StmtKind::Def { name, .. } => format!("def {name}:"),
                StmtKind::Opaque(kind) => format!("opaque {kind:?}"),
            };
            let _ = write!(out, "{pad}{}: {text}", file.line_of(stmt.span.0));
            if let Some(comment) = stmt.trailing {
                let _ = write!(out, "  {}", lossy(file.bytes(comment)));
            }
            out.push('\n');
            if let StmtKind::Def { body, .. } = &stmt.kind {
                render_block(file, body, depth + 1, out);
            }
        }
    }

    fn render_call(file: &File<'_>, call: &Call) -> String {
        let arg = |arg: &Arg| {
            let value = render_value(file, &arg.value);
            match &arg.kind {
                ArgKind::Positional => value,
                ArgKind::Named(name) => format!("{name}={value}"),
                ArgKind::Star => format!("*{value}"),
                ArgKind::StarStar => format!("**{value}"),
            }
        };
        let args: Vec<String> = call.args.iter().map(arg).collect();
        format!("{}({})", call.callee, args.join(", "))
    }

    fn render_value(file: &File<'_>, value: &Value) -> String {
        let list = |items: Vec<String>| items.join(", ");
        match &value.kind {
            ValueKind::Str {
                text,
                inner: Some(_),
            } => format!("{text:?}"),
            ValueKind::Str { text, inner: None } => format!("+{text:?}"),
            ValueKind::Int(n) => n.to_string(),
            ValueKind::Bool(true) => "True".to_string(),
            ValueKind::Bool(false) => "False".to_string(),
            ValueKind::None => "None".to_string(),
            ValueKind::List(items) => {
                format!(
                    "[{}]",
                    list(items.iter().map(|v| render_value(file, v)).collect())
                )
            }
            ValueKind::Dict(entries) => {
                let entry = |(k, v): &(Value, Value)| {
                    format!("{}: {}", render_value(file, k), render_value(file, v))
                };
                format!("{{{}}}", list(entries.iter().map(entry).collect()))
            }
            ValueKind::Ident(name) => format!("${name}"),
            ValueKind::Dynamic => {
                let source = lossy(file.bytes(value.span));
                format!(
                    "<{}>",
                    source.split_whitespace().collect::<Vec<_>>().join(" ")
                )
            }
        }
    }

    fn dialect_of(name: &str) -> Dialect {
        match name {
            _ if name.ends_with("MODULE.bazel") => Dialect::Module,
            _ if name.ends_with(".bzl") => Dialect::Bzl,
            _ if name.contains("WORKSPACE") => Dialect::Workspace,
            _ => Dialect::Build,
        }
    }

    /// The committed corpus: `(file name, bytes)`, sorted.
    fn corpus() -> Vec<(String, Vec<u8>)> {
        let dir = fixtures().join("corpus");
        let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(&dir)
            .expect("corpus directory")
            .map(|entry| entry.expect("corpus entry").path())
            .filter(|path| path.extension().is_none_or(|ext| ext != "golden"))
            .map(|path| {
                let name = path.file_name().unwrap().to_string_lossy().into_owned();
                (name, std::fs::read(&path).expect("corpus file"))
            })
            .collect();
        files.sort();
        files
    }

    /// Real `MODULE.bazel`, `WORKSPACE` and macro files from Bazel, the
    /// rulesets and the Bazel Central Registry (the fixture README lists
    /// where each comes from) read to the committed model.
    #[test]
    fn the_corpus_of_real_files_reads_to_its_goldens() {
        let files = corpus();
        assert_eq!(files.len(), 26, "a corpus file was added or lost");
        let mut seen = BTreeMap::new();
        for (name, bytes) in &files {
            let file = read(bytes, dialect_of(name)).unwrap_or_else(|e| {
                panic!("{name}: Bazel builds this file, so it must read: {e:?}")
            });
            golden(
                &fixtures().join(format!("corpus/{name}.golden")),
                &render(&file),
            );
            *seen.entry(format!("{:?}", file.dialect)).or_insert(0) += 1;
            *seen.entry(format!("{:?}", file.eol)).or_insert(0) += 1;
        }
        // The corpus keeps covering each dialect it claims to, and CRLF.
        let count = |key: &str| seen.get(key).copied().unwrap_or(0);
        assert_eq!(
            (count("Module"), count("Workspace"), count("Bzl")),
            (16, 8, 2)
        );
        assert_eq!((count("Crlf"), count("Mixed")), (1, 0));
    }

    /// What the reader does with one S5 vector: it refuses the file, reads
    /// `V` as a value, or reads the file and has no value for `V`.
    fn verdict(bytes: &[u8], dialect: Dialect) -> String {
        let file = match read(bytes, dialect) {
            Ok(file) => file,
            Err(e) => return format!("refuse {:?}", e.kind),
        };
        let value = file.constant("V", bytes.len()).exact().flatten();
        match value.and_then(Value::as_str) {
            Some(text) => format!("value {text:?} {}", text.len()),
            None => "opaque".to_string(),
        }
    }

    /// Probe S5 ran 60 variants of one statement through Bazel 5.4.1 to
    /// 10.0.0rc3 as a `MODULE.bazel`, an included segment, a `.bzl`, a
    /// `BUILD` file and a `WORKSPACE`. For each the reader's verdict is a
    /// golden, and is checked against what Bazel did (`accepts.tsv`):
    ///
    /// - a value must be the value every accepting Bazel printed, and
    ///   every Bazel that ran the kind must accept;
    /// - a refusal needs every Bazel to have rejected the file, so the
    ///   reader never loses a file Bazel builds;
    /// - anything else must be opaque.
    ///
    /// Every file Bazel ran printed `V`, so the reader must not drop the
    /// statement that did: it reads the `print` call, or names its place
    /// as one it has no model of.
    #[test]
    fn s5_verdicts_agree_with_what_bazel_accepts() {
        let dir = fixtures().join("s5");
        let accepts = std::fs::read_to_string(dir.join("accepts.tsv")).expect("accepts.tsv");
        let (mut out, mut rows) = (String::new(), 0);
        for row in accepts
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let mut cols = row.trim_end_matches('\r').split('\t');
            let (kind, variant) = (cols.next().unwrap(), cols.next().unwrap());
            let outcomes: Vec<&str> = cols.map(|c| c.split_once(" => ").unwrap().1).collect();
            let (set, dialect) = match kind {
                "module" => ("module", Dialect::Module),
                "segment" => ("bare", Dialect::Module),
                "bzl" => ("bare", Dialect::Bzl),
                "build" => ("bare", Dialect::Build),
                "workspace" => ("workspace", Dialect::Workspace),
                other => panic!("unknown kind {other}"),
            };
            let bytes = std::fs::read(dir.join(set).join(variant)).expect("vector");
            let verdict = verdict(&bytes, dialect);
            let rejected = outcomes.iter().all(|o| *o == "error");
            match verdict.split_once(' ') {
                Some(("value", value)) => {
                    assert_eq!(outcomes, [value], "{kind}/{variant}: Bazel disagrees")
                }
                Some(("refuse", _)) => {
                    assert!(rejected, "{kind}/{variant}: refused, and Bazel reads it")
                }
                _ => assert_eq!(verdict, "opaque"),
            }
            if let Ok(file) = read(&bytes, dialect) {
                let print = file.calls("print");
                let kept = !print.seen().is_empty() || !print.reasons().is_empty();
                assert!(kept || rejected, "{kind}/{variant}: the print is dropped");
            }
            let _ = writeln!(out, "{kind}\t{variant}\t{verdict}");
            rows += 1;
        }
        assert_eq!(rows, 301, "60 variants per kind, and one more for .bzl");
        golden(&dir.join("verdicts.golden"), &out);
    }

    /// What the reader makes of the `include` statements of one file: it
    /// refuses the file, or says for each statement that calls `include`
    /// whether it is an include with a known label and `dev_dependency`.
    fn include_verdict(bytes: &[u8]) -> String {
        let file = match read(bytes, Dialect::Module) {
            Ok(file) => file,
            Err(e) => return format!("refuse {:?}", e.kind),
        };
        let calls = file.calls("include");
        let one = |stmt: &&Stmt| match &stmt.kind {
            StmtKind::Include(include) => match include.exact() {
                Some((label, dev)) => format!("include {label:?} dev={dev}"),
                None => "inexact".to_string(),
            },
            _ => "not a statement".to_string(),
        };
        let seen: Vec<String> = calls.seen().iter().map(one).collect();
        match (calls.reasons().is_empty(), seen.is_empty()) {
            (false, _) => format!("incomplete {}", seen.join("; ")),
            (true, true) => "none".to_string(),
            (true, false) => seen.join("; "),
        }
    }

    /// Probe S1c ran 27 spellings and placements of `include()` in a root
    /// `MODULE.bazel` through `bazel mod graph` on nine releases from
    /// 6.6.0 to 10.0.0rc3 (`s1c/accepts.tsv`). What the reader makes of
    /// each file is a golden, and is held against what Bazel did:
    ///
    /// - a file some Bazel evaluated reads, and every include in it is
    ///   exact: an include Bazel follows is never lost, which is why a
    ///   `+` of string literals is folded;
    /// - `dev_dependency` is read, and only 9.3.2 and 10.0.0rc3 took it.
    ///
    /// The reverse is not asked. Bazel rejects labels the statement
    /// reader has no opinion on (`@//...`, a name that does not end in
    /// `.MODULE.bazel`); those belong to the label reader.
    #[test]
    fn s1c_include_rows_agree_with_what_bazel_accepts() {
        let dir = fixtures().join("s1c");
        let accepts = std::fs::read_to_string(dir.join("accepts.tsv")).expect("accepts.tsv");
        let (mut out, mut exact_rows) = (String::new(), Vec::new());
        for row in accepts
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
        {
            let mut cols = row.trim_end_matches('\r').split('\t');
            let name = cols.next().unwrap();
            let outcomes = cols.map(|c| c.split_once(" => ").unwrap());
            // The releases that ran the file to the end: `ok`, or
            // `skipped` under `--ignore_dev_dependency`.
            let evaluated: Vec<&str> = outcomes
                .filter(|(_, outcome)| *outcome != "error")
                .flat_map(|(versions, _)| versions.split(','))
                .collect();
            let bytes = std::fs::read(dir.join("rows").join(name)).expect("row");
            let verdict = include_verdict(&bytes);
            let exact = verdict.split("; ").all(|v| v.starts_with("include \""));
            assert!(
                exact || evaluated.is_empty(),
                "{name}: Bazel {evaluated:?} follows an include the reader lost: {verdict}"
            );
            if bytes.windows(14).any(|w| w == b"dev_dependency") {
                assert!(exact, "{name}: {verdict}");
                assert_eq!(evaluated, ["9.3.2", "10.0.0rc3"], "{name}");
            }
            if exact {
                exact_rows.push(name);
            }
            let _ = writeln!(out, "{name}\t{verdict}");
        }
        assert_eq!(out.lines().count(), 27);
        // The rows design 2.9 rests on.
        for name in [
            "dev_dependency-True",
            "dev_dependency-False",
            "dev_dependency-True+ignore_dev",
            "nonliteral-concat",
            "single-quotes",
            "trailing-comma-multiline",
            "trailing-comment",
        ] {
            assert!(exact_rows.contains(&name), "{name}");
        }
        golden(&dir.join("verdicts.golden"), &out);
    }

    /// The inputs are byte-real: line endings, a byte-order mark, a NUL
    /// and bytes that are not UTF-8 are what several of them test, so a
    /// checkout that converted one, or an edit, would turn a case into
    /// another case without failing it. `SHA256SUMS` lists every file but
    /// itself and the goldens, which are what the reader produces.
    #[test]
    fn the_fixture_inputs_are_the_bytes_that_were_committed() {
        fn files(dir: &Path, out: &mut BTreeSet<PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("fixture directory") {
                let path = entry.expect("directory entry").path();
                if path.is_dir() {
                    files(&path, out);
                } else {
                    out.insert(path);
                }
            }
        }
        let dir = fixtures();
        let mut on_disk = BTreeSet::new();
        files(&dir, &mut on_disk);
        assert!(on_disk.remove(&dir.join("SHA256SUMS")));
        on_disk.retain(|path| path.extension().is_none_or(|ext| ext != "golden"));

        let sums = std::fs::read_to_string(dir.join("SHA256SUMS")).expect("SHA256SUMS");
        let mut listed = BTreeSet::new();
        for line in sums.lines() {
            let (digest, rel) = line.split_once("  ").expect("`<sha256>  <path>`");
            let bytes = std::fs::read(dir.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
            assert_eq!(crate::utils::digest::sha256_hex_of(&bytes), digest, "{rel}");
            listed.insert(dir.join(rel));
        }
        assert_eq!(listed, on_disk);
        assert_eq!(listed.len(), 239);
        // No fixture has the name of a file Bazel takes for a boundary.
        let boundary = [
            "MODULE.bazel",
            "MODULE.bazel.lock",
            "WORKSPACE",
            "WORKSPACE.bazel",
            "WORKSPACE.bzlmod",
            "REPO.bazel",
            "BUILD",
            "BUILD.bazel",
        ];
        let name = |path: &PathBuf| path.file_name().unwrap().to_string_lossy().into_owned();
        assert!(!on_disk
            .iter()
            .any(|path| boundary.contains(&name(path).as_str())));
    }

    /// Everything the reader hands out must index the file it read.
    fn check_invariants(file: &File<'_>) {
        let len = file.src.len();
        let ordered = |span: Span| span.0 <= span.1 && span.1 <= len;
        let mut end = 0;
        for token in &file.tokens {
            assert!(end <= token.start && token.start < token.end && token.end <= len);
            end = token.end;
            if let Tok::Str { inner, plain } = token.tok {
                assert!(token.start < inner.0 && inner.0 <= inner.1 && inner.1 < token.end);
                let printable = file.bytes(inner).iter().all(|b| (0x20..=0x7E).contains(b));
                assert!(!plain || printable, "a plain string is printable ASCII");
            }
        }
        assert!(file.comments.iter().all(|c| ordered(c.span)));
        assert!(file.bindings.iter().all(|b| ordered(b.span)));
        fn walk(file: &File<'_>, stmts: &[Stmt], from: usize, to: usize) {
            let mut at = from;
            for stmt in stmts {
                assert!(at <= stmt.span.0 && stmt.span.0 < stmt.span.1 && stmt.span.1 <= to);
                at = stmt.span.1;
                if let StmtKind::Def { body, .. } = &stmt.kind {
                    walk(file, body, stmt.span.0, stmt.span.1);
                }
                let comments = stmt.leading.iter().chain(&stmt.trailing);
                assert!(comments
                    .into_iter()
                    .all(|c| file.bytes(*c).starts_with(b"#")));
            }
        }
        walk(file, &file.stmts, 0, len);
    }

    /// Read `bytes` in every dialect and run every query and the edit over
    /// the result. The edit must restore the file byte for byte.
    fn exercise(bytes: &[u8]) {
        for dialect in [
            Dialect::Module,
            Dialect::Workspace,
            Dialect::Bzl,
            Dialect::Build,
        ] {
            let Ok(file) = read(bytes, dialect) else {
                continue;
            };
            check_invariants(&file);
            let _ = render(&file);
            for name in ["bazel_dep", "maven", "go_repository", "V", "f", "include"] {
                let _ = (
                    file.calls(name),
                    file.tags(name),
                    file.constant(name, bytes.len()),
                );
                let defs = file
                    .stmts
                    .iter()
                    .filter(|s| matches!(s.kind, StmtKind::Def { .. }));
                defs.for_each(|def| drop(file.calls_in(def, name)));
            }
            let plain = file.tokens.iter().find_map(|t| match t.tok {
                Tok::Str { inner, plain: true } => Some(inner),
                _ => None,
            });
            let Some(inner) = plain else { continue };
            let old = String::from_utf8(file.bytes(inner).to_vec()).unwrap();
            match replace_string_inner(&file, inner, &old, "1.2.3-socket.0a1b2c3d") {
                Ok(edited) => {
                    let again = read(&edited, dialect).expect("an edit result reads");
                    let inner = (inner.0, inner.0 + "1.2.3-socket.0a1b2c3d".len());
                    let back = replace_string_inner(&again, inner, "1.2.3-socket.0a1b2c3d", &old);
                    assert_eq!(
                        back.as_deref(),
                        Ok(bytes),
                        "the inverse edit is the identity"
                    );
                }
                Err(e) => assert!(
                    matches!(e, EditError::MixedLineEndings | EditError::BindsName),
                    "{e:?}"
                ),
            }
        }
    }

    /// No input makes the reader panic, loop or hand out a span outside
    /// the file: every corpus file, S5 vector and S1c row, truncated at
    /// random offsets and with random bytes replaced, inserted and removed.
    #[test]
    fn truncated_and_mutated_inputs_never_panic() {
        // Bytes that change what the lexer is doing when they appear.
        const BYTES: &[u8] =
            b"\"'\\#()[]{},=:;.*+-\n\r\t \0\x0c\x80\xe9\xef\xbb\xbfrdefilambda0x9_";
        let mut inputs: Vec<Vec<u8>> = corpus().into_iter().map(|(_, bytes)| bytes).collect();
        for set in ["s5/module", "s5/workspace", "s5/bare", "s1c/rows"] {
            // Sorted: the order a directory lists its entries in is the
            // file system's, and the cases drawn below follow it.
            let entries = std::fs::read_dir(fixtures().join(set)).expect("vector set");
            let mut paths: Vec<PathBuf> = entries.map(|e| e.expect("entry").path()).collect();
            paths.sort();
            inputs.extend(paths.iter().map(|p| std::fs::read(p).expect("vector")));
        }
        assert_eq!(inputs.len(), 26 + 181 + 27);
        let mut rng = Rng::new(0x5714);
        let mut cases = 0;
        for bytes in &inputs {
            exercise(bytes);
            // A CRLF copy of each file is a file too.
            if !bytes.contains(&b'\r') {
                exercise(&lossy(bytes).replace('\n', "\r\n").into_bytes());
            }
            // Large files get fewer cases each, so the sweep stays fast.
            let rounds = (60_000 / (bytes.len() + 200)).clamp(4, 40);
            for _ in 0..rounds {
                let mut mutated = bytes.clone();
                if rng.chance(40) && !mutated.is_empty() {
                    mutated.truncate(rng.below(mutated.len()));
                }
                for _ in 0..rng.below(4) {
                    let at = rng.below(mutated.len() + 1);
                    let byte = BYTES[rng.below(BYTES.len())];
                    match rng.below(3) {
                        0 => mutated.insert(at, byte),
                        1 if at < mutated.len() => mutated[at] = byte,
                        _ if at < mutated.len() => drop(mutated.remove(at)),
                        _ => {}
                    }
                }
                exercise(&mutated);
                cases += 1;
            }
        }
        assert!(cases > 2_000, "only {cases} mutated cases ran");
    }

    /// Brackets, `def`s and strings nest without recursion in the lexer
    /// and with a bounded one in the reader, so no input can exhaust the
    /// stack (the Gradle tokenizer's VJ-S2).
    #[test]
    fn deep_nesting_is_bounded() {
        let deep = 100_000;
        let list = format!("x = {}{}\n", "[".repeat(deep), "]".repeat(deep));
        let file = read(list.as_bytes(), Dialect::Module).unwrap();
        assert!(matches!(
            &file.stmts[0].kind,
            StmtKind::ConstBind { value, .. } if !value.is_literal()
        ));
        let call = format!("f({}1{})\n", "g(".repeat(deep), ")".repeat(deep));
        assert_eq!(
            read(call.as_bytes(), Dialect::Module).unwrap().stmts.len(),
            1
        );
        let defs: String = (0..1_000)
            .map(|i| format!("{}def f():\n", " ".repeat(i)))
            .collect();
        let file = read(defs.as_bytes(), Dialect::Bzl).unwrap();
        assert_eq!(file.stmts.len(), 1);
        // A target nests like a value, and its brackets are walked once.
        let pattern = format!("{}a{} = 1\n", "(".repeat(deep), ")".repeat(deep));
        let file = read(pattern.as_bytes(), Dialect::Bzl).unwrap();
        assert_eq!(file.bindings.len(), 1);
        let index = format!("a{}[b]{} = 1\n", "[".repeat(deep), "]".repeat(deep));
        let file = read(index.as_bytes(), Dialect::Bzl).unwrap();
        assert_eq!((file.bindings.len(), file.uses("b").other.len()), (0, 1));
    }

    /// A query costs what the uses of its name cost, and not the size of
    /// the file: a caller asks about every proxy and every constant of a
    /// file, and a file may be [`MAX_FILE_BYTES`] of them. Each file here
    /// is at that size. The test takes seconds; with one pass over the
    /// file, its bindings or its statements for each query or each use it
    /// took over six minutes in a release build, so the bound is far from
    /// both.
    #[test]
    fn a_query_costs_what_its_name_costs_at_the_size_cap() {
        fn module(src: &str) -> (File<'_>, usize) {
            assert!(src.len() <= MAX_FILE_BYTES && src.len() > MAX_FILE_BYTES * 9 / 10);
            let file = read(src.as_bytes(), Dialect::Module).expect("a file at the cap reads");
            (file, src.len())
        }
        const EXT: &str = "m = use_extension(\"//:e.bzl\", \"e\")\n";
        let started = std::time::Instant::now();

        // One proxy with a tag on most lines, and one name bound on the
        // others.
        let src = format!(
            "{EXT}{}{}",
            "a=1\n".repeat(124_993),
            "m.x()\n".repeat(91_428)
        );
        let (file, end) = module(&src);
        assert_eq!(file.tags("m").exact().unwrap().len(), 91_428);
        assert_eq!(file.constant("a", end).reasons().len(), 124_993);
        assert_eq!(file.calls("a").reasons().len(), 124_993);

        // A proxy on every line, and every query about each.
        let proxy = |n: usize| format!("p{n} = use_extension(\"//:e.bzl\", \"e\")\n");
        let src: String = (0..26_000).map(proxy).collect();
        let (file, end) = module(&src);
        for n in 0..26_000 {
            let name = format!("p{n}");
            assert_eq!(file.tags(&name).exact(), Some(vec![]), "{name}");
            assert_eq!(file.calls(&name).exact(), Some(vec![]), "{name}");
            let value = file.constant(&name, end);
            assert_eq!(value.reasons().len(), 1, "{name}");
        }

        // A constant on every line.
        let constant = |n: usize| format!("c{n} = [{n}]\n");
        let src: String = (0..60_000).map(constant).collect();
        let (file, end) = module(&src);
        for n in 0..60_000 {
            let value = file.constant(&format!("c{n}"), end);
            assert!(value.exact().flatten().is_some(), "c{n}");
        }

        // One call that is handed a name on every argument, and a tag on
        // every line that is handed a list.
        let handed = format!("f({})\n", "m, ".repeat(150_000));
        let src = format!("{EXT}L = []\n{handed}{}", "m.x(L)\n".repeat(80_000));
        let (file, end) = module(&src);
        let tags = file.tags("m");
        assert_eq!((tags.seen().len(), tags.reasons().len()), (80_000, 150_000));
        assert!(file.constant("L", end).exact().is_some());
        assert_eq!(file.calls("f").exact().unwrap().len(), 1);

        let took = started.elapsed();
        assert!(took.as_secs() < 120, "the queries took {took:?}");
    }
}
