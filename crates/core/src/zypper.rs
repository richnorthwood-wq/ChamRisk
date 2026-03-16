use crate::models::{
    PackageChange, PackageLock, PackageRow, PackageUpdate, RepositoryRow, UpdateAction, VendorGroup,
};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;

pub fn parse_zypper_dry_run(output: &str) -> Vec<PackageUpdate> {
    if output.contains("| Repository") || output.contains("+----") {
        parse_table(output)
    } else {
        parse_verbose(output)
    }
}

pub fn parse_packages_xml(xml: &str) -> Result<Vec<PackageRow>, String> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut rows: Vec<PackageRow> = Vec::new();
    let mut current: Option<PackageRow> = None;
    let mut in_summary = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let raw = tag_name(&e)?;
                let tag = tag_local_name(&raw);
                if tag == "summary" && current.is_some() {
                    in_summary = true;
                } else if is_package_tag(tag, &e) {
                    current = package_row_from_attrs(&e);
                }
            }
            Ok(Event::Empty(e)) => {
                let raw = tag_name(&e)?;
                let tag = tag_local_name(&raw);
                if is_package_tag(tag, &e) {
                    if let Some(row) = package_row_from_attrs(&e) {
                        rows.push(row);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let raw = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let tag = tag_local_name(&raw);
                if tag == "summary" {
                    in_summary = false;
                } else if tag == "package" || tag == "solvable" {
                    if let Some(row) = current.take() {
                        rows.push(row);
                    }
                    in_summary = false;
                }
            }
            Ok(Event::Text(e)) => {
                if in_summary {
                    let text = e
                        .unescape()
                        .map_err(|err| format!("xml parse error: {err}"))?;
                    let text = text.trim();
                    if !text.is_empty() {
                        if let Some(row) = current.as_mut() {
                            row.summary = Some(text.to_string());
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(err) => return Err(format!("xml parse error: {err}")),
        }
        buf.clear();
    }

    Ok(rows)
}

pub fn parse_search_solvables_xml(xml: &str) -> Result<Vec<PackageRow>, String> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut rows: Vec<PackageRow> = Vec::new();
    let mut current: Option<PackageRow> = None;
    let mut in_summary = false;

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let raw = tag_name(&e)?;
                let tag = tag_local_name(&raw);
                if tag == "summary" && current.is_some() {
                    in_summary = true;
                } else if is_package_tag(tag, &e) {
                    current = package_row_from_attrs(&e);
                }
            }
            Ok(Event::Empty(e)) => {
                let raw = tag_name(&e)?;
                let tag = tag_local_name(&raw);
                if is_package_tag(tag, &e) {
                    if let Some(row) = package_row_from_attrs(&e) {
                        rows.push(row);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let raw = String::from_utf8_lossy(e.name().as_ref()).to_string();
                let tag = tag_local_name(&raw);
                if tag == "summary" {
                    in_summary = false;
                } else if tag == "package" || tag == "solvable" {
                    if let Some(row) = current.take() {
                        rows.push(row);
                    }
                    in_summary = false;
                }
            }
            Ok(Event::Text(e)) => {
                if in_summary {
                    let text = e
                        .unescape()
                        .map_err(|err| format!("xml parse error: {err}"))?;
                    let text = text.trim();
                    if !text.is_empty() {
                        if let Some(row) = current.as_mut() {
                            row.summary = Some(text.to_string());
                        }
                    }
                }
            }
            Ok(_) => {}
            Err(err) => return Err(format!("xml parse error: {err}")),
        }
        buf.clear();
    }

    Ok(rows)
}

pub fn parse_repositories_xml(xml: &str) -> Result<Vec<RepositoryRow>, String> {
    let mut reader = Reader::from_str(xml);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut rows = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let raw = tag_name(&e)?;
                let tag = tag_local_name(&raw);
                if tag == "repo" {
                    rows.push(repository_row_from_attrs(&e));
                }
            }
            Ok(_) => {}
            Err(err) => return Err(format!("xml parse error: {err}")),
        }
        buf.clear();
    }

    Ok(rows)
}

pub fn parse_package_locks(output: &str) -> Vec<PackageLock> {
    let header_map = output
        .lines()
        .map(str::trim)
        .filter(|line| line.contains('|'))
        .map(split_pipe_row)
        .find(|cols| is_lock_header_row(cols))
        .map(|cols| lock_column_map(&cols));

    output
        .lines()
        .filter_map(|line| parse_package_lock_row(line, header_map.as_ref()))
        .collect()
}

fn parse_package_lock_row(line: &str, header_map: Option<&LockColumnMap>) -> Option<PackageLock> {
    let trimmed = line.trim();
    if trimmed.is_empty() || !trimmed.contains('|') {
        return None;
    }

    let cols = split_pipe_row(trimmed);
    if cols.len() < 2 {
        return None;
    }
    if is_lock_divider_row(&cols) || is_lock_header_row(&cols) {
        return None;
    }

    let map = header_map
        .cloned()
        .unwrap_or_else(|| LockColumnMap::with_fallback(&cols));
    let lock_id = get_col(&cols, &map.lock_id).and_then(parse_lock_id);
    let name = get_col(&cols, &map.name).and_then(opt)?;
    let match_type = get_col(&cols, &map.match_type).and_then(opt);
    let repository = get_col(&cols, &map.repository).and_then(opt);
    let comment = get_col(&cols, &map.comment).and_then(opt);

    Some(PackageLock {
        lock_id,
        name,
        match_type,
        repository,
        comment,
        raw_entry: trimmed.to_string(),
    })
}

fn parse_lock_id(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if !trimmed.is_empty() && trimmed.chars().all(|ch| ch.is_ascii_digit()) {
        Some(trimmed.to_string())
    } else {
        None
    }
}

fn is_lock_divider_row(cols: &[&str]) -> bool {
    cols.iter().all(|col| {
        let normalized: String = col.chars().filter(|ch| !ch.is_whitespace()).collect();
        !normalized.is_empty() && normalized.chars().all(|ch| ch == '-' || ch == '+')
    })
}

fn is_lock_header_row(cols: &[&str]) -> bool {
    let normalized: Vec<String> = cols
        .iter()
        .filter_map(|col| normalize_header_name(col))
        .collect();

    normalized
        .iter()
        .any(|col| matches!(col.as_str(), "name" | "type" | "matchtype" | "id"))
        && normalized
            .iter()
            .any(|col| matches!(col.as_str(), "name" | "type" | "matchtype"))
}

#[derive(Debug, Clone, Default)]
struct LockColumnMap {
    lock_id: Option<usize>,
    name: Option<usize>,
    match_type: Option<usize>,
    repository: Option<usize>,
    comment: Option<usize>,
}

impl LockColumnMap {
    fn with_fallback(cols: &[&str]) -> Self {
        let (lock_id, offset) = match cols.first().and_then(|value| parse_lock_id(value)) {
            Some(_) => (Some(0), 1),
            None => (None, 0),
        };

        Self {
            lock_id,
            name: cols.get(offset).map(|_| offset),
            match_type: cols.get(offset + 1).map(|_| offset + 1),
            repository: cols.get(offset + 2).map(|_| offset + 2),
            comment: cols.get(offset + 3).map(|_| offset + 3),
        }
    }
}

fn lock_column_map(cols: &[&str]) -> LockColumnMap {
    let mut map = LockColumnMap::default();

    for (idx, col) in cols.iter().enumerate() {
        let raw = col.trim();
        match normalize_header_name(col).as_deref() {
            Some("id") => map.lock_id = Some(idx),
            Some("name") | Some("package") => map.name = Some(idx),
            Some("type") | Some("matchtype") => map.match_type = Some(idx),
            Some("repository") | Some("repo") => map.repository = Some(idx),
            Some("comment") | Some("description") => map.comment = Some(idx),
            _ if raw == "#" => map.lock_id = Some(idx),
            _ => {}
        }
    }

    map
}

fn parse_table(output: &str) -> Vec<PackageUpdate> {
    let header_cols = output
        .lines()
        .filter(|l| l.trim_start().starts_with('|'))
        .map(split_pipe_row)
        .find(|cols| {
            cols.iter()
                .any(|col| normalize_header_name(col).as_deref() == Some("repository"))
        });
    let column_map = header_cols
        .as_ref()
        .map(|cols| table_column_map(cols))
        .unwrap_or_default();

    output
        .lines()
        .filter(|l| l.trim_start().starts_with('|'))
        .filter_map(|line| {
            let cols = split_pipe_row(line);

            if cols.is_empty() {
                return None;
            }

            // Header / divider rows.
            if cols.iter().any(|c| c.contains("---"))
                || cols
                    .iter()
                    .any(|col| normalize_header_name(col).as_deref() == Some("repository"))
            {
                return None;
            }
            let column_map = column_map.with_fallback(&cols);
            let repository = get_col(&cols, &column_map.repository)?;
            let name = get_col(&cols, &column_map.name)?;
            let current_version = get_col(&cols, &column_map.current).unwrap_or("-");
            let new_version = get_col(&cols, &column_map.new).unwrap_or("-");
            let status = get_col(&cols, &column_map.status).unwrap_or("unknown");
            let vendor = column_map
                .vendor
                .and_then(|idx| cols.get(idx).copied())
                .and_then(opt);
            let arch = get_col(&cols, &column_map.arch).and_then(opt);

            let action = map_action(status);

            // “->” sometimes shows up in vendor column when changes occur.
            let vendor_arrow = vendor.as_deref().unwrap_or("").contains("->");
            let status_lc = status.to_ascii_lowercase();

            let repo_change =
                status_lc.contains("from") || status_lc.contains("repo") || vendor_arrow;
            let vendor_change = status_lc.contains("vendor") || vendor_arrow;

            Some(PackageUpdate {
                repository: opt(repository),
                name: (*name).to_string(),
                current_version: opt(current_version),
                new_version: opt(new_version),
                arch,
                vendor_group: derive_vendor_group(opt(repository), vendor.clone()),
                vendor,
                action,
                vendor_change,
                repo_change,
            })
        })
        .collect()
}

fn parse_verbose(output: &str) -> Vec<PackageUpdate> {
    let mut updates = Vec::new();
    let mut cur = PackageUpdate {
        name: String::new(),
        action: UpdateAction::Unknown,
        current_version: None,
        new_version: None,
        arch: None,
        repository: None,
        vendor: None, // <-- ADDED
        vendor_group: VendorGroup::Unknown,
        vendor_change: false,
        repo_change: false,
    };

    for line in output.lines() {
        let l = line.trim();
        if l.starts_with("Package:") {
            if !cur.name.is_empty() {
                updates.push(cur.clone());
            }
            cur = PackageUpdate {
                name: l.trim_start_matches("Package:").trim().to_string(),
                action: UpdateAction::Unknown,
                current_version: None,
                new_version: None,
                arch: None,
                repository: None,
                vendor: None,
                vendor_group: VendorGroup::Unknown,
                vendor_change: false,
                repo_change: false,
            };
        } else if l.starts_with("Action:") {
            cur.action = map_action(l.trim_start_matches("Action:").trim());
        } else if l.starts_with("Current Version:") {
            cur.current_version = opt(l.trim_start_matches("Current Version:").trim());
        } else if l.starts_with("New Version:") {
            cur.new_version = opt(l.trim_start_matches("New Version:").trim());
        } else if l.starts_with("Arch:") {
            cur.arch = opt(l.trim_start_matches("Arch:").trim());
        } else if l.starts_with("Repository:") {
            cur.repository = opt(l.trim_start_matches("Repository:").trim());
            cur.vendor_group = derive_vendor_group(cur.repository.clone(), cur.vendor.clone());
        } else if l.starts_with("Vendor:") {
            cur.vendor = opt(l.trim_start_matches("Vendor:").trim());
            cur.vendor_group = derive_vendor_group(cur.repository.clone(), cur.vendor.clone());
        } else if l.starts_with("Vendor Change:") {
            cur.vendor_change = l.ends_with("yes");
        } else if l.starts_with("Repo Change:") {
            cur.repo_change = l.ends_with("yes");
        }
    }
    if !cur.name.is_empty() {
        updates.push(cur);
    }
    updates
}

#[derive(Debug, Default)]
struct TableColumnMap {
    repository: Option<usize>,
    name: Option<usize>,
    current: Option<usize>,
    new: Option<usize>,
    status: Option<usize>,
    vendor: Option<usize>,
    arch: Option<usize>,
}

impl TableColumnMap {
    fn with_fallback(&self, cols: &[&str]) -> Self {
        if self.repository.is_some()
            && self.name.is_some()
            && self.current.is_some()
            && self.new.is_some()
            && self.status.is_some()
        {
            return Self {
                repository: self.repository,
                name: self.name,
                current: self.current,
                new: self.new,
                status: self.status,
                vendor: self.vendor,
                arch: self.arch,
            };
        }

        let offset = if cols.len() >= 6 && cols[0].len() <= 2 && !cols[0].contains('/') {
            1
        } else {
            0
        };
        let has_vendor = cols.len() >= 7 + offset;

        Self {
            repository: Some(offset),
            name: Some(offset + 1),
            current: Some(offset + 2),
            new: Some(offset + 3),
            status: Some(offset + 4),
            vendor: has_vendor.then_some(offset + 5),
            arch: Some(offset + if has_vendor { 6 } else { 5 }),
        }
    }
}

fn split_pipe_row(line: &str) -> Vec<&str> {
    let mut cols: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
    if cols.first().map(|s| s.is_empty()).unwrap_or(false) {
        cols.remove(0);
    }
    if cols.last().map(|s| s.is_empty()).unwrap_or(false) {
        cols.pop();
    }
    cols
}

fn normalize_header_name(value: &str) -> Option<String> {
    let normalized = value
        .trim()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn table_column_map(cols: &[&str]) -> TableColumnMap {
    let mut map = TableColumnMap::default();

    for (idx, col) in cols.iter().enumerate() {
        match normalize_header_name(col).as_deref() {
            Some("repository") | Some("repo") => map.repository = Some(idx),
            Some("name") | Some("package") => map.name = Some(idx),
            Some("current") | Some("currentversion") | Some("edition") => map.current = Some(idx),
            Some("new") | Some("newversion") => map.new = Some(idx),
            Some("status") | Some("action") => map.status = Some(idx),
            Some("vendor") => map.vendor = Some(idx),
            Some("arch") | Some("architecture") => map.arch = Some(idx),
            _ => {}
        }
    }

    map
}

fn get_col<'a>(cols: &'a [&str], idx: &Option<usize>) -> Option<&'a str> {
    idx.and_then(|idx| cols.get(idx).copied())
}

fn derive_vendor_group(repository: Option<String>, vendor: Option<String>) -> VendorGroup {
    if vendor.as_deref().map(|s| !s.is_empty()).unwrap_or(false) {
        return VendorGroup::Unknown;
    }

    let Some(repository) = repository else {
        return VendorGroup::Unknown;
    };

    let repo = repository.to_ascii_lowercase();
    if repo.contains("packman") {
        VendorGroup::Packman
    } else if repo.contains("repo-oss")
        || repo.contains("repo-non-oss")
        || repo.contains("repo-update")
        || repo.contains("opensuse")
        || repo.contains("tumbleweed")
    {
        VendorGroup::Official
    } else if repo.is_empty() {
        VendorGroup::Unknown
    } else {
        VendorGroup::ThirdParty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_verbose_resets_fields_on_new_package() {
        let input = "\
Package: foo
Action: upgrade
Repository: repo-oss
Vendor: openSUSE
Package: bar
Action: install
";

        let updates = parse_verbose(input);

        assert_eq!(updates.len(), 2);
        assert_eq!(updates[0].name, "foo");
        assert_eq!(updates[0].repository.as_deref(), Some("repo-oss"));
        assert_eq!(updates[1].name, "bar");
        assert_eq!(updates[1].repository, None);
        assert_eq!(updates[1].vendor, None);
    }

    #[test]
    fn parse_table_uses_header_named_vendor_column() {
        let input = "\
| Name | Repository | Current Version | New Version | Status | Vendor | Arch |
| mesa | repo-oss | 1 | 2 | upgrade | openSUSE | x86_64 |
";

        let updates = parse_table(input);

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].name, "mesa");
        assert_eq!(updates[0].repository.as_deref(), Some("repo-oss"));
        assert_eq!(updates[0].vendor.as_deref(), Some("openSUSE"));
    }

    #[test]
    fn vendor_group_falls_back_to_repository_when_vendor_missing() {
        let input = "\
| Repository | Name | Current Version | New Version | Status | Arch |
| packman | ffmpeg | 1 | 2 | upgrade | x86_64 |
";

        let updates = parse_table(input);

        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].vendor, None);
        assert_eq!(updates[0].vendor_group, VendorGroup::Packman);
    }

    #[test]
    fn parse_package_locks_reads_table_rows_with_ids() {
        let input = "\
| # | Name | Type | Repository |
|---+------+-------+------------|
| 1 | MozillaFirefox | package | (any) |
| 2 | kernel-default | package | repo-oss |
";

        let locks = parse_package_locks(input);

        assert_eq!(locks.len(), 2);
        assert_eq!(locks[0].lock_id.as_deref(), Some("1"));
        assert_eq!(locks[0].name, "MozillaFirefox");
        assert_eq!(locks[0].match_type.as_deref(), Some("package"));
        assert_eq!(locks[0].repository.as_deref(), Some("(any)"));
        assert_eq!(locks[0].comment, None);
        assert_eq!(
            locks[0].raw_entry,
            "| 1 | MozillaFirefox | package | (any) |"
        );
    }

    #[test]
    fn parse_package_locks_supports_rows_without_ids() {
        let input = "\
| Name | Type |
| MozillaFirefox | package |
";

        let locks = parse_package_locks(input);

        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].lock_id, None);
        assert_eq!(locks[0].name, "MozillaFirefox");
        assert_eq!(locks[0].match_type.as_deref(), Some("package"));
        assert_eq!(locks[0].repository, None);
        assert_eq!(locks[0].comment, None);
    }

    #[test]
    fn parse_package_locks_reads_repository_and_comment_columns() {
        let input = "\
| # | Name | Type | Repository | Comment |
|---+------+-------+------------+---------|
| 1 | MozillaFirefox | package | repo-oss | browser hold |
";

        let locks = parse_package_locks(input);

        assert_eq!(locks.len(), 1);
        assert_eq!(locks[0].lock_id.as_deref(), Some("1"));
        assert_eq!(locks[0].repository.as_deref(), Some("repo-oss"));
        assert_eq!(locks[0].comment.as_deref(), Some("browser hold"));
    }

    #[test]
    fn parse_repositories_xml_reads_repository_rows() {
        let input = r#"
<stream>
  <repo-list>
    <repo alias="repo-oss" name="Main Repository (OSS)" enabled="1" gpgcheck="1" autorefresh="1" priority="99" uri="http://example.invalid/oss" type="rpm-md"/>
    <repo alias="packman" name="Packman" enabled="0" gpgcheck="0" autorefresh="0" priority="70" uri="http://packman.invalid/suse" type="rpm-md"/>
  </repo-list>
</stream>
"#;

        let repos = parse_repositories_xml(input).expect("parse");

        assert_eq!(repos.len(), 2);
        assert_eq!(repos[0].alias, "repo-oss");
        assert_eq!(repos[0].name, "Main Repository (OSS)");
        assert_eq!(repos[0].enabled, Some(true));
        assert_eq!(repos[0].gpg_check, Some(true));
        assert_eq!(repos[0].refresh, Some(true));
        assert_eq!(repos[0].priority.as_deref(), Some("99"));
        assert_eq!(repos[0].uri.as_deref(), Some("http://example.invalid/oss"));
        assert_eq!(repos[0].repo_type.as_deref(), Some("rpm-md"));
        assert_eq!(repos[1].enabled, Some(false));
        assert_eq!(repos[1].gpg_check, Some(false));
        assert_eq!(repos[1].refresh, Some(false));
    }

    #[test]
    fn parse_repositories_xml_preserves_blank_optional_fields() {
        let input = r#"
<stream>
  <repo-list>
    <repo alias="custom" name="Custom Repo"/>
  </repo-list>
</stream>
"#;

        let repos = parse_repositories_xml(input).expect("parse");

        assert_eq!(repos.len(), 1);
        assert_eq!(repos[0].alias, "custom");
        assert_eq!(repos[0].name, "Custom Repo");
        assert_eq!(repos[0].enabled, None);
        assert_eq!(repos[0].gpg_check, None);
        assert_eq!(repos[0].refresh, None);
        assert_eq!(repos[0].priority, None);
        assert_eq!(repos[0].uri, None);
        assert_eq!(repos[0].repo_type, None);
    }

    #[test]
    fn parse_search_solvables_reads_summary_attribute() {
        let input = r#"
<stream>
  <solvable-list>
    <solvable kind="package" name="nano" status="installed" edition="7.2-1" arch="x86_64" repository="OSS" summary="Nano editor"/>
  </solvable-list>
</stream>
"#;

        let rows = parse_search_solvables_xml(input).expect("parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "nano");
        assert_eq!(rows[0].summary.as_deref(), Some("Nano editor"));
    }

    #[test]
    fn parse_search_solvables_reads_summary_tag_text() {
        let input = r#"
<stream>
  <solvable-list>
    <solvable type="package" name="vim" status="not-installed" edition="9.0-1" arch="x86_64" repository="OSS">
      <summary>Vi IMproved editor</summary>
    </solvable>
  </solvable-list>
</stream>
"#;

        let rows = parse_search_solvables_xml(input).expect("parse");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "vim");
        assert_eq!(rows[0].summary.as_deref(), Some("Vi IMproved editor"));
    }
}

fn tag_local_name(name: &str) -> &str {
    name.rsplit(':').next().unwrap_or(name)
}

fn is_package_tag(tag: &str, e: &BytesStart) -> bool {
    if tag == "package" {
        true
    } else if tag == "solvable" {
        // zypper --xmlout output varies by subcommand/version.
        // Common patterns:
        // - <solvable type="package" ... />
        // - <solvable kind="package" ... />
        attr_value(e, "type").as_deref() == Some("package")
            || attr_value(e, "kind").as_deref() == Some("package")
    } else {
        false
    }
}

fn package_row_from_attrs(e: &BytesStart) -> Option<PackageRow> {
    let name = attr_value(e, "name")?;
    let available_version = first_attr(
        e,
        &[
            "edition",
            "version",
            "edition-new",
            "edition_new",
            "version-new",
            "version_new",
        ],
    );
    let arch = attr_value(e, "arch");
    let repository = first_attr(
        e,
        &[
            "repository",
            "repo",
            "repository-alias",
            "repository_alias",
            "repository-name",
            "repository_name",
        ],
    );
    let summary = attr_value(e, "summary");

    // For `zypper --xmlout search -s -t package ""`, `<solvable>` includes `status="installed"`.
    // In that feed, `edition` represents the installed edition for installed packages.
    let installed_version = match attr_value(e, "status").as_deref() {
        Some("installed") => available_version.clone(),
        _ => None,
    };

    Some(PackageRow {
        name,
        installed_version,
        available_version,
        repository,
        arch,
        summary,
    })
}

fn repository_row_from_attrs(e: &BytesStart) -> RepositoryRow {
    RepositoryRow {
        alias: first_attr(e, &["alias", "repoalias", "repo_alias"]).unwrap_or_default(),
        name: first_attr(e, &["name", "repo-name", "repo_name"]).unwrap_or_default(),
        enabled: first_attr(e, &["enabled", "is-enabled", "is_enabled", "enabled-state"])
            .and_then(parse_boolish_attr),
        gpg_check: first_attr(
            e,
            &[
                "gpgcheck",
                "gpg-check",
                "gpg_check",
                "gpgcheck-enabled",
                "gpgcheck_enabled",
            ],
        )
        .and_then(parse_boolish_attr),
        refresh: first_attr(
            e,
            &["autorefresh", "refresh", "auto-refresh", "auto_refresh"],
        )
        .and_then(parse_boolish_attr),
        priority: first_attr(e, &["priority", "prio"]),
        uri: first_attr(e, &["uri", "url", "baseurl", "base-uri", "base_uri"]),
        repo_type: first_attr(e, &["type", "repo-type", "repo_type"]),
    }
}

fn parse_boolish_attr(value: String) -> Option<bool> {
    let normalized = value.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "1" | "yes" | "true" | "on" | "enabled" => Some(true),
        "0" | "no" | "false" | "off" | "disabled" => Some(false),
        _ => None,
    }
}

fn map_action(v: &str) -> UpdateAction {
    let v = v.to_lowercase();
    if v.contains("install") {
        UpdateAction::Install
    } else if v.contains("upgrade") || v.contains("update") {
        UpdateAction::Upgrade
    } else if v.contains("downgrade") {
        UpdateAction::Downgrade
    } else if v.contains("remove") || v.contains("delete") {
        UpdateAction::Remove
    } else if v.contains("vendor") {
        UpdateAction::VendorChange
    } else if v.contains("repo") {
        UpdateAction::RepoChange
    } else {
        UpdateAction::Unknown
    }
}

fn opt(v: &str) -> Option<String> {
    let v = v.trim();
    if v.is_empty() || v == "-" {
        None
    } else {
        Some(v.to_string())
    }
}

pub fn build_preview_dup_xml_args(include_details: bool) -> Vec<String> {
    let mut args = vec![
        "--non-interactive".to_string(),
        "--xmlout".to_string(),
        "dup".to_string(),
        "--dry-run".to_string(),
    ];
    if include_details {
        args.push("--details".to_string());
    }
    args
}

pub fn parse_preview_xml(stdout: &str) -> Result<Vec<PackageChange>, String> {
    let mut reader = Reader::from_str(stdout);
    reader.trim_text(true);

    let mut buf = Vec::new();
    let mut changes: Vec<PackageChange> = Vec::new();
    let mut action_stack: Vec<UpdateAction> = Vec::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Eof) => break,
            Ok(Event::Start(e)) => {
                let name = tag_name(&e)?;
                if let Some(action) = action_from_tag(&name) {
                    action_stack.push(action);
                }
                if is_solvable_tag(&name) {
                    if let Some(change) = change_from_attrs(&e, current_action(&action_stack)) {
                        changes.push(change);
                    }
                }
            }
            Ok(Event::Empty(e)) => {
                let name = tag_name(&e)?;
                if is_solvable_tag(&name) {
                    if let Some(change) = change_from_attrs(&e, current_action(&action_stack)) {
                        changes.push(change);
                    }
                }
            }
            Ok(Event::End(e)) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).to_string();
                if action_from_tag(&name).is_some() {
                    action_stack.pop();
                }
            }
            Ok(_) => {}
            Err(err) => return Err(format!("xml parse error: {err}")),
        }
        buf.clear();
    }

    // DEBUG: prove whether kernel is present in parsed output
    eprintln!("changes total = {}", changes.len());
    for c in changes
        .iter()
        .filter(|c| c.name.contains("kernel"))
        .take(20)
    {
        eprintln!(
            "KERNEL: name={} action={:?} from={:?} to={:?} repo={:?}",
            c.name, c.action, c.from, c.to, c.repo
        );
    }

    Ok(changes)
}

fn current_action(stack: &[UpdateAction]) -> UpdateAction {
    stack.last().cloned().unwrap_or(UpdateAction::Unknown)
}

fn tag_name(e: &BytesStart) -> Result<String, String> {
    std::str::from_utf8(e.name().as_ref())
        .map(|name| name.to_string())
        .map_err(|err| format!("invalid utf8 tag: {err}"))
}

fn is_solvable_tag(name: &str) -> bool {
    matches!(name, "solvable" | "package" | "patch" | "pattern")
}

fn action_from_tag(name: &str) -> Option<UpdateAction> {
    let n = name.rsplit(':').next().unwrap_or(name);

    match n {
        "install" => Some(UpdateAction::Install),
        "upgrade" | "update" | "reinstall" => Some(UpdateAction::Upgrade),
        "downgrade" => Some(UpdateAction::Downgrade),
        "remove" | "delete" | "erase" => Some(UpdateAction::Remove),

        // zypper --xmlout dup --dry-run wrappers (THIS is what you have)
        "to-install" | "to_install" => Some(UpdateAction::Install),
        "to-upgrade" | "to_upgrade" => Some(UpdateAction::Upgrade),
        "to-downgrade" | "to_downgrade" => Some(UpdateAction::Downgrade),
        "to-remove" | "to_remove" => Some(UpdateAction::Remove),
        "to-reinstall" | "to_reinstall" => Some(UpdateAction::Upgrade),

        _ => None,
    }
}

fn change_from_attrs(e: &BytesStart, action: UpdateAction) -> Option<PackageChange> {
    let name = attr_value(e, "name")?;
    let arch = attr_value(e, "arch");
    let repo = repo_value(e);
    let vendor = vendor_value(e);
    let kind = attr_value(e, "type")
        .or_else(|| attr_value(e, "kind"))
        .or_else(|| attr_value(e, "category"));

    let from_directional = first_attr(
        e,
        &[
            "edition-old",
            "edition_old",
            "version-old",
            "version_old",
            "edition-installed",
            "edition_installed",
            "edition-from",
            "edition_from",
            "version-installed",
            "version_installed",
            "version-from",
            "version_from",
        ],
    );
    let from_fallback = first_attr(
        e,
        &[
            "edition-old",
            "edition_old",
            "version-old",
            "version_old",
            "edition-installed",
            "edition_installed",
            "edition-from",
            "edition_from",
            "version-installed",
            "version_installed",
            "version-from",
            "version_from",
            "edition",
            "version",
        ],
    );
    let from_plain = first_attr(e, &["edition", "version"]);
    let to_candidate = first_attr(
        e,
        &[
            "edition-to",
            "edition_to",
            "edition-new",
            "edition_new",
            "edition",
            "version-to",
            "version_to",
            "version-new",
            "version_new",
            "version",
        ],
    );

    let (from, to) = match action {
        UpdateAction::Install => (None, to_candidate),
        UpdateAction::Remove => (from_fallback, None),
        UpdateAction::Upgrade | UpdateAction::Downgrade => {
            (from_directional.or(from_plain), to_candidate)
        }
        _ => (from_fallback, to_candidate),
    };

    Some(PackageChange {
        name,
        arch,
        action,
        from,
        to,
        repo,
        vendor,
        kind,
    })
}

fn first_attr(e: &BytesStart, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|key| attr_value(e, key))
}

fn format_from_to(from: Option<String>, to: Option<String>) -> Option<String> {
    match (from, to) {
        (Some(from), Some(to)) if from != to => Some(format!("{from} -> {to}")),
        (Some(_), Some(to)) => Some(to),
        (Some(from), None) => Some(from),
        (None, Some(to)) => Some(to),
        (None, None) => None,
    }
}

fn repo_value(e: &BytesStart) -> Option<String> {
    let repository_from =
        attr_value(e, "repository-from").or_else(|| attr_value(e, "repository_from"));
    let repository_to = attr_value(e, "repository-to").or_else(|| attr_value(e, "repository_to"));
    if let Some(value) = format_from_to(repository_from.clone(), repository_to.clone()) {
        return Some(value);
    }

    if let Some(to) = repository_to {
        return Some(to);
    }
    if let Some(repo) = attr_value(e, "repository") {
        return Some(repo);
    }
    if let Some(repo) = attr_value(e, "repo") {
        return Some(repo);
    }
    if let Some(from) = repository_from {
        return Some(from);
    }

    if let Some(to) = attr_value(e, "repo-to").or_else(|| attr_value(e, "repo_to")) {
        return Some(to);
    }
    if let Some(from) = attr_value(e, "repo-from").or_else(|| attr_value(e, "repo_from")) {
        return Some(from);
    }

    None
}

fn vendor_value(e: &BytesStart) -> Option<String> {
    let vendor_from = first_attr(
        e,
        &[
            "vendor-from",
            "vendor_from",
            "from-vendor",
            "from_vendor",
            "old-vendor",
            "old_vendor",
        ],
    )
    .or_else(|| attr_value_by_normalized_key(e, "vendorfrom"));
    let vendor_to = first_attr(
        e,
        &[
            "vendor-to",
            "vendor_to",
            "to-vendor",
            "to_vendor",
            "new-vendor",
            "new_vendor",
        ],
    )
    .or_else(|| attr_value_by_normalized_key(e, "vendorto"));

    if let Some(value) = format_from_to(vendor_from.clone(), vendor_to.clone()) {
        return Some(value);
    }
    if let Some(to) = vendor_to {
        return Some(to);
    }
    if let Some(vendor) = attr_value(e, "vendor")
        .or_else(|| attr_value(e, "vendor-name"))
        .or_else(|| attr_value(e, "vendor_name"))
        .or_else(|| attr_value_by_normalized_key(e, "vendor"))
    {
        return Some(vendor);
    }
    if let Some(from) = vendor_from {
        return Some(from);
    }

    None
}

fn attr_value(e: &BytesStart, key: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find(|a| a.key.as_ref() == key.as_bytes())
        .and_then(|a| String::from_utf8(a.value.into_owned()).ok())
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v != "-")
}

fn attr_value_by_normalized_key(e: &BytesStart, key: &str) -> Option<String> {
    e.attributes()
        .flatten()
        .find_map(|attr| {
            let raw = std::str::from_utf8(attr.key.as_ref()).ok()?;
            let normalized = raw
                .chars()
                .filter(|ch| ch.is_ascii_alphanumeric())
                .collect::<String>()
                .to_ascii_lowercase();
            if normalized == key {
                String::from_utf8(attr.value.into_owned()).ok()
            } else {
                None
            }
        })
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty() && v != "-")
}
