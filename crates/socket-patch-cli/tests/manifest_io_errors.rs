//! Filesystem failures must not be mistaken for a missing manifest.

#[cfg(unix)]
#[test]
fn unreadable_manifest_parent_is_an_error_for_every_mutating_command() {
    use std::os::unix::fs::PermissionsExt;

    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let socket = tmp.path().join(".socket");
    std::fs::create_dir(&socket).unwrap();
    std::fs::write(socket.join("manifest.json"), r#"{"patches":{}}"#).unwrap();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o000)).unwrap();

    let outputs: Vec<_> = ["apply", "repair", "vendor", "rollback", "remove"]
        .into_iter()
        .map(|command| {
            let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_socket-patch"));
            child
                .env_clear()
                .current_dir(tmp.path())
                .args([command, "--offline", "--json"]);
            if command == "remove" {
                child.arg("11111111-1111-4111-8111-111111111111");
            }
            (command, child.output().unwrap())
        })
        .collect();
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o755)).unwrap();

    for (command, output) in outputs {
        assert_eq!(output.status.code(), Some(1), "{command}: {output:?}");
        let envelope: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            envelope["error"]["code"], "lock_io",
            "{command}: {envelope}"
        );
    }
}
