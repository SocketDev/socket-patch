//! One recognizer per ruleset (design 2.7). A recognizer turns the tags of
//! `MODULE.bazel` and the calls of the `WORKSPACE` family into hubs: the
//! lock labels a ruleset reads, the user's patch and override
//! declarations, and whatever else its own `<Ruleset>Detail` records.
//!
//! Files are named by ruleset, never by ecosystem word, so no other
//! compatibility workflow's file-name glob fires on a Bazel change.
//!
//! Every recognizer has the one signature below and a row in [`ALL`], so
//! the fixpoint reader calls them through the table and a recognizer
//! package replaces its own file without editing this one.

pub mod aspect_rules_py;
pub mod gazelle;
pub mod pip_compile;
pub mod report_only;
pub mod rules_csharp;
pub mod rules_dotnet;
pub mod rules_js;
pub mod rules_jvm_external;
pub mod rules_nodejs;
pub mod rules_pycross;
pub mod rules_python;
pub mod rules_rs;
pub mod rules_ruby;
pub mod rules_rust;

use super::model::{
    BazelLine, EffectiveFlags, FileView, Gap, Hub, ModuleLock, ModuleModel, OutOfScope, Ruleset,
    RulesetSignal, WorkspaceModel,
};

/// What a recognizer may read. `None` means the root has no such file. A
/// file that exists and cannot be read arrives as its reader's own
/// unreadable value, never as `None`: unreadable is not absent.
pub struct RecognizeInput<'a> {
    /// The root `MODULE.bazel` with its literal `include()` closure.
    pub module: Option<&'a ModuleModel>,
    pub workspace_files: &'a [WorkspaceModel],
    pub module_lock: Option<&'a ModuleLock>,
    /// `None` = no tracked rc file.
    pub flags: Option<&'a EffectiveFlags>,
    /// `None` = no evidence of the Bazel line; a version gate then fails.
    pub line: Option<&'a BazelLine>,
    /// Lock headers, generated `.bzl` files and bounded BUILD scans.
    pub files: &'a dyn FileView,
}

/// What one recognizer found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Recognized {
    pub hubs: Vec<Hub>,
    /// The ruleset is present and no hub could be resolved: its ecosystem
    /// is undetermined workspace-wide.
    pub signals: Vec<RulesetSignal>,
    pub out_of_scope: OutOfScope,
    /// Statements that could define a hub and could not be read exactly.
    pub gaps: Vec<Gap>,
}

/// A recognizer: pure, total, and silent on a workspace without its
/// ruleset.
pub type RecognizeFn = fn(&RecognizeInput<'_>) -> Recognized;

/// Every recognizer, in [`Ruleset::ALL`] order.
pub const ALL: &[(Ruleset, RecognizeFn)] = &[
    (Ruleset::RulesJs, rules_js::recognize),
    (Ruleset::RulesNodejs, rules_nodejs::recognize),
    (Ruleset::RulesPython, rules_python::recognize),
    (Ruleset::AspectRulesPy, aspect_rules_py::recognize),
    (Ruleset::RulesPycross, rules_pycross::recognize),
    (Ruleset::RulesJvmExternal, rules_jvm_external::recognize),
    (Ruleset::Gazelle, gazelle::recognize),
    (Ruleset::RulesRust, rules_rust::recognize),
    (Ruleset::RulesRs, rules_rs::recognize),
    (Ruleset::RulesRuby, rules_ruby::recognize),
    (Ruleset::RulesDotnet, rules_dotnet::recognize),
    (Ruleset::RulesCsharp, rules_csharp::recognize),
    (Ruleset::ReportOnly, report_only::recognize),
];

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bazel::model::FileText;

    struct NoFiles;
    impl FileView for NoFiles {
        fn read(&self, _: &str) -> FileText {
            FileText::Absent
        }
        fn list(&self, _: &str) -> Option<Vec<String>> {
            Some(Vec::new())
        }
    }

    #[test]
    fn every_ruleset_has_one_recognizer_and_one_file() {
        let listed: Vec<Ruleset> = ALL.iter().map(|(ruleset, _)| *ruleset).collect();
        assert_eq!(listed, Ruleset::ALL);
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/bazel/rulesets");
        for ruleset in Ruleset::ALL {
            let file = dir.join(format!("{}.rs", ruleset.name()));
            assert!(file.is_file(), "{} is missing", file.display());
        }
    }

    /// Holds for the stubs and for every recognizer that replaces one: a
    /// root with no `MODULE.bazel`, no `WORKSPACE` file and no lock has no
    /// hub, no signal and no gap. A recognizer that invented one here
    /// would make Bazel govern a project it does not build.
    #[test]
    fn an_empty_workspace_has_no_hub() {
        let input = RecognizeInput {
            module: None,
            workspace_files: &[],
            module_lock: None,
            flags: None,
            line: None,
            files: &NoFiles,
        };
        for (ruleset, recognize) in ALL {
            assert_eq!(recognize(&input), Recognized::default(), "{ruleset:?}");
        }
    }
}
