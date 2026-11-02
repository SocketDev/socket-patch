//! pnpm's install record, `node_modules/.modules.yaml`: JSON on pnpm 10+,
//! YAML before. Its top-level fields are read here, once, so the crawler,
//! the version gate and the redirect upstream agree on quoting and on
//! which of two duplicate keys wins (#1918).

use crate::formats::text::strip_bom;

/// The top-level string `key` of a `.modules.yaml`: from the JSON object
/// on pnpm 10+, else the last top-level YAML scalar (the shared pnpm
/// settings reader, [`super::workspace::top_level_scalar`]). An empty
/// value is `Some("")`; callers that read empty as unset filter it.
pub(crate) fn field(text: &str, key: &str) -> Option<String> {
    let text = strip_bom(text);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(text) {
        return value.get(key)?.as_str().map(str::to_string);
    }
    super::workspace::top_level_scalar(text, key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_json_and_yaml_records_alike() {
        for text in [
            "{\"packageManager\":\"pnpm@9.1.0\"}",
            "\u{feff}{\"packageManager\":\"pnpm@9.1.0\"}",
            "packageManager: pnpm@9.1.0\n",
            "\u{feff}layoutVersion: 5\npackageManager: 'pnpm@9.1.0'\n",
            "packageManager: pnpm@8.0.0\npackageManager: \"pnpm@9.1.0\" # last\n",
        ] {
            assert_eq!(
                field(text, "packageManager").as_deref(),
                Some("pnpm@9.1.0"),
                "{text:?}"
            );
        }
        assert_eq!(field("{}", "packageManager"), None);
        assert_eq!(field("{\"packageManager\":1}", "packageManager"), None);
        assert_eq!(
            field("packageManager: ''\n", "packageManager").as_deref(),
            Some("")
        );
        assert_eq!(field("layoutVersion: 5\n", "packageManager"), None);
    }
}
