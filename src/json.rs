//! Minimal JSON writer for logs and manifests. Output only; the tool never
//! parses JSON, so a full serialization dependency is not warranted.

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
        Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }

    pub fn strings<S: AsRef<str>>(items: &[S]) -> Json {
        Json::Arr(
            items
                .iter()
                .map(|s| Json::Str(s.as_ref().to_string()))
                .collect(),
        )
    }

    /// Compact single-line rendering (one record per line in JSONL logs).
    pub fn render(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Int(n) => out.push_str(&n.to_string()),
            Json::Str(s) => write_string(s, out),
            Json::Arr(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Json::Obj(pairs) => {
                out.push('{');
                for (i, (key, value)) in pairs.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_string(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

impl From<&str> for Json {
    fn from(s: &str) -> Json {
        Json::Str(s.to_string())
    }
}

impl From<String> for Json {
    fn from(s: String) -> Json {
        Json::Str(s)
    }
}

impl From<bool> for Json {
    fn from(b: bool) -> Json {
        Json::Bool(b)
    }
}

impl From<u32> for Json {
    fn from(n: u32) -> Json {
        Json::Int(i64::from(n))
    }
}

impl From<u64> for Json {
    fn from(n: u64) -> Json {
        Json::Int(i64::try_from(n).unwrap_or(i64::MAX))
    }
}

impl From<usize> for Json {
    fn from(n: usize) -> Json {
        Json::Int(i64::try_from(n).unwrap_or(i64::MAX))
    }
}

impl<T: Into<Json>> From<Option<T>> for Json {
    fn from(v: Option<T>) -> Json {
        v.map(Into::into).unwrap_or(Json::Null)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_windows_paths_and_control_characters() {
        let value = Json::from("C:\\Users\\jdoe\n\"x\"\u{1}");
        assert_eq!(value.render(), r#""C:\\Users\\jdoe\n\"x\"\u0001""#);
    }

    #[test]
    fn renders_nested_structures_in_order() {
        let value = Json::obj(vec![
            ("a", Json::Int(1)),
            ("b", Json::strings(&["x", "y"])),
            ("c", Json::from(None::<String>)),
            ("d", Json::obj(vec![("e", true.into())])),
        ]);
        assert_eq!(
            value.render(),
            r#"{"a":1,"b":["x","y"],"c":null,"d":{"e":true}}"#
        );
    }
}
