use crate::models::{PackageUpdate, UpdateAction};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAssessment {
    pub level: RiskLevel,
    pub score_sum: i32,
    pub score_max: i32,
    pub reasons: Vec<String>, // top reasons, highest risk first
}

pub fn assess_package_risk(update: &PackageUpdate) -> RiskLevel {
    let crit = criticality_weight(&update.name);
    let bump = match (
        update.current_version.as_deref(),
        update.new_version.as_deref(),
    ) {
        (Some(from), Some(to)) => version_bump_weight(from, to),
        _ => 1,
    };
    let score = action_base_risk(&update.action) + supply_chain_risk(update) + crit + bump;

    let mut level = if score >= 10 {
        RiskLevel::High
    } else if score >= 7 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    if matches!(
        update.action,
        UpdateAction::Remove | UpdateAction::Downgrade
    ) {
        level = level.max(RiskLevel::Medium);
    }

    level
}

pub fn report_risk_label(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "green",
        RiskLevel::Medium => "amber",
        RiskLevel::High => "red",
    }
}

pub fn assess_risk(updates: &[PackageUpdate]) -> RiskAssessment {
    let mut sum = 0i32;
    let mut max = 0i32;
    let mut reasons_scored: Vec<(i32, String)> = Vec::new();
    let mut has_systemd = false;
    let mut has_systemd_upgrade = false;
    let mut has_kernel = false;
    let mut has_glibc = false;
    let mut has_pam = false;
    let mut has_dracut = false;
    let mut has_grub2 = false;
    let mut critical_remove_or_downgrade = false;
    let mut core_supply_chain_shift = false;

    for u in updates {
        let crit = criticality_weight(&u.name);
        let bump = match (u.current_version.as_deref(), u.new_version.as_deref()) {
            (Some(from), Some(to)) => version_bump_weight(from, to),
            _ => 1, // Unknown magnitude is slightly risky.
        };
        let s = action_base_risk(&u.action) + supply_chain_risk(u) + crit + bump;

        // Aggregate
        sum += s;
        if s > max {
            max = s;
        }

        has_systemd |= is_systemd_family(&u.name);
        has_systemd_upgrade |= is_systemd_family(&u.name) && u.action == UpdateAction::Upgrade;
        has_kernel |= is_kernel_family(&u.name);
        has_glibc |= is_glibc_family(&u.name);
        has_pam |= is_pam_family(&u.name);
        has_dracut |= is_dracut_family(&u.name);
        has_grub2 |= is_grub2_family(&u.name);
        critical_remove_or_downgrade |=
            crit >= 5 && matches!(u.action, UpdateAction::Remove | UpdateAction::Downgrade);
        core_supply_chain_shift |= crit >= 4
            && (u.vendor_change
                || u.repo_change
                || matches!(
                    u.action,
                    UpdateAction::VendorChange | UpdateAction::RepoChange
                ));

        // Capture reasons for notable items
        if s >= 7 {
            let mut why = Vec::new();

            why.push(format_action(&u.action).to_string());

            if crit >= 4 {
                why.push("critical".to_string());
            } else if crit >= 2 {
                why.push("important".to_string());
            }

            if u.vendor_change {
                why.push("vendor-change".to_string());
            }
            if u.repo_change {
                why.push("repo-change".to_string());
            }

            if let (Some(_), Some(_)) = (u.current_version.as_deref(), u.new_version.as_deref()) {
                if bump >= 3 {
                    why.push("major-bump".to_string());
                } else if bump == 2 {
                    why.push("minor-bump".to_string());
                }
            }

            let ver = match (u.current_version.as_deref(), u.new_version.as_deref()) {
                (Some(a), Some(b)) => format!("{a} → {b}"),
                (Some(a), None) => format!("{a} → ?"),
                (None, Some(b)) => format!("? → {b}"),
                (None, None) => "? → ?".to_string(),
            };

            reasons_scored.push((s, format!("pkg {} [{ver}] ({})", u.name, why.join(", "))));
        }
    }

    // Combine “many” + “single landmine”
    let composite = sum + (max * 2);

    let mut level = if max >= 10 || composite >= 28 {
        RiskLevel::High
    } else if max >= 7 || composite >= 14 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    // Policy floors and transaction-level hazard combinations.
    if has_systemd_upgrade {
        level = level.max(RiskLevel::Medium);
        reasons_scored.push((
            80,
            "tx systemd-family upgrade touches core init/session plumbing".to_string(),
        ));
    }

    if has_systemd && has_kernel {
        level = RiskLevel::High;
        reasons_scored.push((
            100,
            "tx systemd-family + kernel transaction can affect boot and userspace together"
                .to_string(),
        ));
    }

    if has_glibc && has_pam {
        level = RiskLevel::High;
        reasons_scored.push((
            98,
            "tx glibc + pam transaction can break login/auth paths".to_string(),
        ));
    }

    if has_dracut && has_grub2 {
        level = RiskLevel::High;
        reasons_scored.push((
            98,
            "tx dracut + grub2 transaction can break the boot chain".to_string(),
        ));
    }

    if critical_remove_or_downgrade {
        level = RiskLevel::High;
        reasons_scored.push((
            96,
            "tx critical package remove/downgrade is treated as high risk".to_string(),
        ));
    }

    if core_supply_chain_shift {
        level = level.max(RiskLevel::Medium);
        reasons_scored.push((
            82,
            "tx core package vendor/repo shift raises supply-chain risk".to_string(),
        ));
    }

    reasons_scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let reasons = reasons_scored
        .into_iter()
        .take(6)
        .map(|(_, r)| r)
        .collect::<Vec<_>>();

    RiskAssessment {
        level,
        score_sum: sum,
        score_max: max,
        reasons,
    }
}

fn criticality_weight(name: &str) -> i32 {
    // Keep this explicit and boring. It’s maintainable.
    let n = name;

    // boot/kernel/base userspace
    if is_kernel_family(n) || is_dracut_family(n) || is_grub2_family(n) || is_boot_chain_family(n) {
        return 5;
    }
    if is_systemd_family(n) || is_glibc_family(n) {
        return 5;
    }
    if is_pam_family(n)
        || is_base_system_family(n)
        || is_dbus_family(n)
        || is_ca_family(n)
        || is_release_family(n)
    {
        return 4;
    }

    if n.starts_with("gcc") || n.starts_with("llvm") || n.starts_with("clang") {
        return 3;
    }

    // security / auth / crypto
    if n.starts_with("openssl") || n.starts_with("gnutls") || n.starts_with("nss") {
        return 4;
    }
    // networking
    if n.starts_with("NetworkManager")
        || n.starts_with("wicked")
        || n.starts_with("nftables")
        || n.starts_with("iptables")
        || n.starts_with("firewalld")
    {
        return 3;
    }

    // storage/fs
    if n.starts_with("btrfsprogs") || n.starts_with("cryptsetup") || n.starts_with("lvm2") {
        return 4;
    }

    // graphics/desktop “fragile”
    if n.starts_with("nvidia")
        || n.starts_with("mesa")
        || n.starts_with("xorg")
        || n.starts_with("wayland")
        || n.starts_with("kwin")
    {
        return 3;
    }
    //toolchain transitions
    if n.starts_with("gcc")
        || n.starts_with("clang")
        || n.starts_with("rust")
        || n.starts_with("cargo")
        || n.starts_with("cmake")
        || n.starts_with("binutils")
    {
        return 3;
    }
    //package managers
    if n.starts_with("rpm") || n.starts_with("libzypp") || n.starts_with("zypper") {
        return 3;
    }
    // desktop support
    if n.starts_with("qt") || n.starts_with("gtk") {
        return 2;
    }
    0
}

fn action_base_risk(action: &UpdateAction) -> i32 {
    match action {
        UpdateAction::Remove | UpdateAction::Downgrade => 5,
        UpdateAction::VendorChange | UpdateAction::RepoChange => 3,
        UpdateAction::Upgrade => 2,
        UpdateAction::Install => 1,
        UpdateAction::Unknown => 2,
    }
}

fn supply_chain_risk(update: &PackageUpdate) -> i32 {
    let mut risk = 0;
    if update.vendor_change {
        risk += 3;
    }
    if update.repo_change {
        risk += 2;
    }
    risk
}

fn is_systemd_family(name: &str) -> bool {
    name.starts_with("systemd") || name.starts_with("libsystemd") || name == "udev"
}

fn is_dbus_family(name: &str) -> bool {
    name.starts_with("dbus")
}

fn is_kernel_family(name: &str) -> bool {
    name.starts_with("kernel")
}

fn is_dracut_family(name: &str) -> bool {
    name.starts_with("dracut")
}

fn is_grub2_family(name: &str) -> bool {
    name.starts_with("grub2")
}

fn is_boot_chain_family(name: &str) -> bool {
    name.starts_with("shim") || name.starts_with("mokutil")
}

fn is_glibc_family(name: &str) -> bool {
    name.starts_with("glibc") || name.starts_with("libstdc++")
}

fn is_pam_family(name: &str) -> bool {
    name.starts_with("pam") || name.starts_with("polkit") || name == "sudo"
}

fn is_base_system_family(name: &str) -> bool {
    name.starts_with("aaa_base")
        || name.starts_with("permissions")
        || name.starts_with("util-linux")
        || name.starts_with("filesystem")
}

fn is_ca_family(name: &str) -> bool {
    name.starts_with("ca-certificates")
}

fn is_release_family(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    name.starts_with("opensuse-release")
        || name.starts_with("distribution-release")
        || name.starts_with("system-release")
        || name.starts_with("base-release")
        || name.starts_with("sles-release")
}

fn version_bump_weight(from: &str, to: &str) -> i32 {
    // Cheap heuristic: compare first 3 numeric segments if we can.
    // 0..3
    fn nums(s: &str) -> Vec<i32> {
        let mut out = Vec::new();
        let mut cur = String::new();
        for ch in s.chars() {
            if ch.is_ascii_digit() {
                cur.push(ch);
            } else if !cur.is_empty() {
                if let Ok(v) = cur.parse::<i32>() {
                    out.push(v);
                }
                cur.clear();
                if out.len() >= 3 {
                    break;
                }
            }
        }
        if !cur.is_empty() && out.len() < 3 {
            if let Ok(v) = cur.parse::<i32>() {
                out.push(v);
            }
        }
        out
    }

    let a = nums(from);
    let b = nums(to);
    if a.is_empty() || b.is_empty() {
        return 1; // unknown-ish
    }

    let a0 = *a.get(0).unwrap_or(&0);
    let a1 = *a.get(1).unwrap_or(&0);
    let a2 = *a.get(2).unwrap_or(&0);

    let b0 = *b.get(0).unwrap_or(&0);
    let b1 = *b.get(1).unwrap_or(&0);
    let b2 = *b.get(2).unwrap_or(&0);

    if b0 > a0 {
        3
    } else if b1 > a1 {
        2
    } else if b2 > a2 {
        1
    } else {
        0
    }
}

fn format_action(a: &UpdateAction) -> &'static str {
    match a {
        UpdateAction::Remove => "remove",
        UpdateAction::Downgrade => "downgrade",
        UpdateAction::VendorChange => "vendor-change",
        UpdateAction::RepoChange => "repo-change",
        UpdateAction::Upgrade => "upgrade",
        UpdateAction::Install => "install",
        UpdateAction::Unknown => "unknown",
    }
}

pub fn fingerprint(updates: &[PackageUpdate]) -> String {
    let mut entries: Vec<String> = updates
        .iter()
        .map(|u| {
            format!(
                "{}|{:?}|{}|{}|{}|{}",
                u.name,
                u.action,
                u.current_version.as_deref().unwrap_or(""),
                u.new_version.as_deref().unwrap_or(""),
                u.vendor_change,
                u.repo_change
            )
        })
        .collect();
    entries.sort();
    entries.join(";")
}
