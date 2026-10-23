#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

#[path = "../common/cache_env.rs"]
mod cache_env;
#[path = "../common/hermetic.rs"]
mod hermetic;
#[path = "../common/oracle.rs"]
mod oracle;

const UUID: &str = "d8941a4c-4bcd-4756-b0aa-239ec9c81b0f";
const MODULE: &str = "github.com/jackc/pgx/v5";
const PURL: &str = "pkg:golang/github.com/jackc/pgx/v5@v5.7.0";
const MAIN: &str = r#"package main
import (
    "fmt"
    "github.com/jackc/pgx/v5/pgproto3"
)
func probe() (result string) {
    defer func() { if recover() != nil { result = "PANIC" } }()
    var msg pgproto3.FunctionCall
    if msg.Decode([]byte{0,0,0,1,0,0,0,1,255,255,255,254}) != nil { return "REJECTED" }
    return "ACCEPTED"
}
func main() { fmt.Println(probe()) }
"#;

fn env(cmd: &mut Command, cache: &Path) {
    cache_env::isolate(cmd);
    cmd.env("GOMODCACHE", cache.join("modcache"))
        .env("GOPATH", cache.join("gopath"))
        .env("GOCACHE", cache.join("gocache"))
        .env("GOTOOLCHAIN", "local")
        .env("GOENV", "off")
        .env("GOWORK", "off")
        .env("GOFLAGS", "-mod=readonly")
        .env("GOPRIVATE", "")
        .env("GONOSUMDB", "")
        .env("GONOPROXY", "")
        .env("GOPROXY", "https://proxy.golang.org,direct")
        .env("GOSUMDB", "sum.golang.org");
}

fn go(project: &Path, cache: &Path, args: &[&str]) -> Output {
    let mut cmd = Command::new("go");
    env(&mut cmd, cache);
    cmd.args(args).current_dir(project).output().expect("go")
}

fn success(out: &Output) {
    assert!(
        out.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
}

fn invoke(project: &Path, cache: &Path, args: &[&str]) -> Output {
    let mut cmd = hermetic::command(&oracle::binary());
    env(&mut cmd, cache);
    let out = cmd
        .current_dir(project)
        .args(args)
        .args([
            "--json",
            "--yes",
            "--ecosystems",
            "golang",
            "--proxy-url",
            "https://patches-api.socket.dev",
        ])
        .output()
        .expect("socket-patch");
    out
}

fn cli(project: &Path, cache: &Path, args: &[&str]) -> serde_json::Value {
    let out = invoke(project, cache, args);
    success(&out);
    serde_json::from_slice(&out.stdout).expect("JSON envelope")
}

fn project(root: &Path, name: &str) -> PathBuf {
    let dir = root.join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(
        dir.join("go.mod"),
        format!("module example.com/go-patch-smoke\n\ngo 1.21\n\nrequire {MODULE} v5.7.0\n"),
    )
    .unwrap();
    std::fs::write(dir.join("main.go"), MAIN).unwrap();
    dir
}

fn copy_tree(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).unwrap();
    for entry in std::fs::read_dir(src).unwrap() {
        let entry = entry.unwrap();
        let to = dst.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &to);
        } else {
            std::fs::copy(entry.path(), to).unwrap();
        }
    }
}

pub fn delivery(mode: &str) {
    for entrypoint in ["get", "scan"] {
        let tmp = tempfile::tempdir().unwrap();
        let consumer = project(tmp.path(), "consumer");
        let cache = tmp.path().join("initial");
        success(&go(
            &consumer,
            &cache,
            &["mod", "download", &format!("{MODULE}@v5.7.0")],
        ));
        let before = go(&consumer, &cache, &["run", "."]);
        success(&before);
        assert_eq!(String::from_utf8_lossy(&before.stdout).trim(), "PANIC");
        let args = if entrypoint == "get" {
            vec!["get", UUID, "--mode", mode]
        } else {
            vec!["scan", "--mode", mode]
        };
        let result = cli(&consumer, &cache, &args);
        assert!(
            result["events"].as_array().unwrap().iter().any(|event| {
                event["purl"] == PURL
                    && (event["action"] == "applied" || event["action"] == "redirected")
            }),
            "{mode}/{entrypoint} did not deliver {UUID}: {result:#}"
        );
        let after = go(&consumer, &cache, &["run", "."]);
        success(&after);
        assert_eq!(String::from_utf8_lossy(&after.stdout).trim(), "REJECTED");
        let fresh = tmp.path().join("fresh");
        copy_tree(&consumer, &fresh);
        let run = go(&fresh, &tmp.path().join("empty-cache"), &["run", "."]);
        success(&run);
        assert_eq!(String::from_utf8_lossy(&run.stdout).trim(), "REJECTED");
        if mode != "hosted" {
            success(&go(&consumer, &cache, &["mod", "tidy"]));
            cli(&consumer, &cache, &["rollback", "--offline"]);
            let restored = go(&consumer, &cache, &["run", "."]);
            success(&restored);
            assert_eq!(String::from_utf8_lossy(&restored.stdout).trim(), "PANIC");
        }
    }
}

pub fn cold_agent() {
    let tmp = tempfile::tempdir().unwrap();
    let consumer = project(tmp.path(), "consumer");
    let cache = tmp.path().join("empty-cache");
    let out = invoke(&consumer, &cache, &["get", UUID, "--mode", "agent"]);
    assert!(
        !out.status.success(),
        "a missing module must fail explicitly"
    );
    let result: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(
        result["summary"]["applied"], 0,
        "a cold cache cannot be reported applied: {result}"
    );
    assert!(
        result["events"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["purl"] == PURL
                && e["action"] == "failed"
                && e["errorCode"] == "package_not_installed"),
        "{result}"
    );
    success(&go(
        &consumer,
        &cache,
        &["mod", "download", &format!("{MODULE}@v5.7.0")],
    ));
    cli(&consumer, &cache, &["apply", "--offline"]);
    let after = go(&consumer, &cache, &["run", "."]);
    success(&after);
    assert_eq!(String::from_utf8_lossy(&after.stdout).trim(), "REJECTED");
}
