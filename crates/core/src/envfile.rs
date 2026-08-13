//! Parse and format classic `.env` files.

use models::DecryptedVariable;

/// Parse KEY=VALUE lines. Ignores blank lines and `#` comments.
/// Supports optional single/double quotes around values.
pub fn parse_env(content: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw_val)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = unquote(raw_val.trim());
        out.push((key.to_string(), value));
    }
    out
}

fn unquote(s: &str) -> String {
    if s.len() >= 2 {
        let bytes = s.as_bytes();
        if (bytes[0] == b'"' && bytes[s.len() - 1] == b'"')
            || (bytes[0] == b'\'' && bytes[s.len() - 1] == b'\'')
        {
            return s[1..s.len() - 1].replace("\\\"", "\"").replace("\\n", "\n");
        }
    }
    s.to_string()
}

/// Format decrypted variables as `.env` text.
pub fn format_env(vars: &[DecryptedVariable]) -> String {
    let mut lines = Vec::new();
    for v in vars {
        if !v.allow_export {
            continue;
        }
        let value = if needs_quotes(&v.value) {
            format!("\"{}\"", v.value.replace('\"', "\\\""))
        } else {
            v.value.clone()
        };
        lines.push(format!("{}={}", v.key, value));
    }
    if lines.is_empty() {
        String::new()
    } else {
        lines.join("\n") + "\n"
    }
}

fn needs_quotes(value: &str) -> bool {
    value.is_empty()
        || value
            .chars()
            .any(|c| c.is_whitespace() || c == '#' || c == '"' || c == '\'')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic() {
        let pairs = parse_env("A=1\nB=two\n");
        assert_eq!(
            pairs,
            vec![("A".into(), "1".into()), ("B".into(), "two".into())]
        );
    }

    #[test]
    fn parse_comments_and_quotes() {
        let pairs = parse_env("# hi\nFOO=\"bar baz\"\n\nX='y'\n");
        assert_eq!(
            pairs,
            vec![("FOO".into(), "bar baz".into()), ("X".into(), "y".into()),]
        );
    }

    #[test]
    fn format_quotes_when_needed() {
        let vars = vec![DecryptedVariable {
            id: uuid::Uuid::nil(),
            environment_id: uuid::Uuid::nil(),
            key: "MSG".into(),
            value: "hello world".into(),
            notes: None,
            is_readonly: false,
            allow_export: true,
        }];
        let s = format_env(&vars);
        assert_eq!(s, "MSG=\"hello world\"\n");
    }
}
