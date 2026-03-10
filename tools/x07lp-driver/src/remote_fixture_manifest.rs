use super::*;

const REMOTE_FIXTURE_INDEX_KIND: &str = "lp.remote.fixture.index.internal@0.1.0";

fn remote_fixture_index_path() -> PathBuf {
    root_dir()
        .join("spec")
        .join("fixtures")
        .join("remote-oss")
        .join("fixture_index.json")
}

pub(super) fn remote_fixture_name(raw: Option<&str>) -> Option<String> {
    raw.and_then(|value| {
        Path::new(value)
            .file_name()
            .and_then(OsStr::to_str)
            .map(ToOwned::to_owned)
    })
}

pub(super) fn resolve_remote_fixture_inputs(
    fixture: Option<&str>,
) -> (Option<String>, Option<String>) {
    let fixture_name = remote_fixture_name(fixture);
    let Some(index_doc) = load_json(&remote_fixture_index_path()).ok() else {
        return (None, None);
    };
    if get_str(&index_doc, &["schema_version"]).as_deref() != Some(REMOTE_FIXTURE_INDEX_KIND) {
        return (None, None);
    }
    let items = index_doc
        .get("fixtures")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let requested = fixture_name
        .as_deref()
        .unwrap_or("remote_promote")
        .to_string();
    let resolved_name = resolve_fixture_alias(&items, &requested).unwrap_or(requested);
    let Some(item) = items
        .iter()
        .find(|item| get_str(item, &["name"]).as_deref() == Some(resolved_name.as_str()))
    else {
        return (None, None);
    };
    let plan = get_str(item, &["plan"]).or_else(|| {
        get_str(item, &["dir"]).map(|dir| format!("{}/deploy.plan.json", dir.trim_end_matches('/')))
    });
    let metrics_dir = get_str(item, &["dir"]);
    (plan, metrics_dir)
}

fn resolve_fixture_alias(items: &[Value], requested: &str) -> Option<String> {
    let mut current = requested.to_string();
    let mut seen = BTreeSet::new();
    loop {
        if !seen.insert(current.clone()) {
            return None;
        }
        let item = items
            .iter()
            .find(|item| get_str(item, &["name"]).as_deref() == Some(current.as_str()))?;
        let Some(alias) = get_str(item, &["alias_of"]) else {
            return Some(current);
        };
        current = alias;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_remote_promote_aliases_from_fixture_index() {
        let (plan, metrics_dir) = resolve_remote_fixture_inputs(Some("remote_query"));
        assert_eq!(
            plan.as_deref(),
            Some("spec/fixtures/remote-oss/remote_promote/deploy.plan.json")
        );
        assert_eq!(
            metrics_dir.as_deref(),
            Some("spec/fixtures/remote-oss/remote_promote")
        );
    }
}
