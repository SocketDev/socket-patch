use std::path::Path;

fn parse_major(output: &str) -> Option<u32> {
    output
        .split_whitespace()
        .find_map(|part| part.trim_start_matches('v').split('.').next()?.parse().ok())
}

pub async fn installed_major(root: &Path) -> Option<u32> {
    let mut command = tokio::process::Command::new("pipenv");
    command
        .arg("--version")
        .current_dir(root)
        .kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(10), command.output())
        .await
        .ok()?
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_major(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn installer_version_output() {
        assert_eq!(parse_major("pipenv, version 11.10.4\n"), Some(11));
        assert_eq!(parse_major("pipenv, version 2026.8.0\n"), Some(2026));
        assert_eq!(parse_major("unavailable"), None);
    }
}
