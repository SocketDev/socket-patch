//! Every lock reader that picks "the pure wheel" of a pypi package (uv /
//! PEP 751 inventory, poetry inventory, ledger recovery) goes through the
//! one shared portability rule, so they agree with vendored and hosted
//! mode on the wheels where the old `-none-any.whl` suffix check did not
//! (#1048: interpreter-bound and Python-2-only tags).

use super::*;
use crate::vendor::lock_inventory::recover::pure_wheel_from_uv_unit;
use crate::vendor::pypi_distribution::wheel_platform_from_filename;

const SHA: &str = "abababababababababababababababababababababababababababababababab";

/// `(wheel filename, portable)`: the cases where a suffix check and the
/// shared tag classifier used to differ, plus the ones they always agreed on.
const WHEELS: &[(&str, bool)] = &[
    ("six-1.16.0-py2.py3-none-any.whl", true),
    ("six-1.16.0-py3-none-any.whl", true),
    ("six-1.16.0-py38-none-any.whl", true),
    ("six-1.16.0-cp311-none-any.whl", false),
    ("six-1.16.0-pp310-none-any.whl", false),
    ("six-1.16.0-py2-none-any.whl", false),
    ("six-1.16.0-cp312-abi3-any.whl", false),
    ("six-1.16.0-cp312-cp312-manylinux_2_17_x86_64.whl", false),
];

fn uv_unit(file: &str) -> String {
    format!(
        "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\n\
         source = {{ registry = \"https://pypi.org/simple\" }}\n\
         wheels = [{{ url = \"https://files.pythonhosted.org/packages/aa/{file}\", hash = \"sha256:{SHA}\" }}]\n"
    )
}

#[test]
fn the_table_matches_the_shared_classifier() {
    for &(file, portable) in WHEELS {
        assert_eq!(!wheel_platform_from_filename(file).0, portable, "{file}");
    }
}

#[test]
fn uv_inventory_and_ledger_recovery_pick_the_same_wheels() {
    for &(file, portable) in WHEELS {
        let unit = uv_unit(file);
        let entries = python_lock_inventory(&format!("version = 1\n\n{unit}")).unwrap();
        let [six] = entries.as_slice() else {
            panic!("{file}: {entries:?}")
        };
        let expected =
            portable.then(|| format!("https://files.pythonhosted.org/packages/aa/{file}"));
        assert_eq!(six.resolved, expected, "inventory, {file}");
        assert_eq!(
            six.integrity,
            if portable {
                LockIntegrity::Sha256Hex(SHA.into())
            } else {
                LockIntegrity::None
            },
            "inventory, {file}"
        );
        assert_eq!(
            pure_wheel_from_uv_unit(&unit).map(|(url, _)| url),
            expected,
            "recovery, {file}"
        );
    }
}

#[test]
fn uv_inventory_reads_the_wheel_name_before_a_query_or_fragment() {
    for suffix in ["?download=1", "#sha256=00"] {
        let unit = uv_unit(&format!("six-1.16.0-py3-none-any.whl{suffix}"));
        let entries = python_lock_inventory(&format!("version = 1\n\n{unit}")).unwrap();
        assert!(entries[0].resolved.is_some(), "{suffix}: {entries:?}");
        assert!(pure_wheel_from_uv_unit(&unit).is_some(), "{suffix}");
    }
}

#[tokio::test]
async fn poetry_inventory_pins_only_a_portable_wheel() {
    for &(file, portable) in WHEELS {
        let lock = format!(
            "[[package]]\nname = \"six\"\nversion = \"1.16.0\"\nfiles = [\n    {{file = \"{file}\", hash = \"sha256:{SHA}\"}},\n]\n\n[metadata]\nlock-version = \"2.1\"\n"
        );
        let tmp = tempfile::tempdir().unwrap();
        tokio::fs::write(tmp.path().join("poetry.lock"), lock)
            .await
            .unwrap();
        let entries = inventory_pypi_locks(tmp.path()).await.unwrap();
        let six = entries.iter().find(|e| e.name == "six").unwrap();
        assert_eq!(
            six.integrity,
            if portable {
                LockIntegrity::Sha256Hex(SHA.into())
            } else {
                LockIntegrity::None
            },
            "poetry, {file}"
        );
    }
}
