use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

#[derive(Serialize)]
struct Finding {
    id: &'static str,
    severity: &'static str,
    path: String,
    line: usize,
    message: String,
    evidence: String,
}

struct Patterns {
    aws_key: Regex,
    github_token: Regex,
    slack_token: Regex,
    private_key: Regex,
    assignment: Regex,
    action_use: Regex,
}

impl Patterns {
    fn compile() -> Result<Self, String> {
        Ok(Self {
            aws_key: Regex::new(r"\bAKIA[0-9A-Z]{16}\b").map_err(|error| error.to_string())?,
            github_token: Regex::new(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b").map_err(|error| error.to_string())?,
            slack_token: Regex::new(r"\bxox[baprs]-[A-Za-z0-9-]{12,}\b").map_err(|error| error.to_string())?,
            private_key: Regex::new(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----").map_err(|error| error.to_string())?,
            assignment: Regex::new(r#"(?i)(?:api[_-]?key|secret|token|password)\s*[:=]\s*['"]?([A-Za-z0-9/+=_.-]{12,})"#)
                .map_err(|error| error.to_string())?,
            action_use: Regex::new(r"(?i)^\s*uses\s*:\s*([^\s#]+)").map_err(|error| error.to_string())?,
        })
    }
}

pub fn run(paths: &[PathBuf], base: Option<&str>, json_output: bool) -> Result<bool, String> {
    let files = if let Some(base) = base {
        changed_files(base)?
    } else {
        collect_paths(paths)?
    };
    let patterns = Patterns::compile()?;
    let mut findings = Vec::new();
    for path in files {
        scan_file(&path, &patterns, &mut findings)?;
    }
    findings.sort_by(|left, right| (&left.path, left.line, left.id).cmp(&(&right.path, right.line, right.id)));
    if json_output {
        println!("{}", serde_json::to_string_pretty(&findings).map_err(|error| error.to_string())?);
    } else if findings.is_empty() {
        println!("hashrail scan: no findings");
    } else {
        for finding in &findings {
            println!("{} {} {}:{} {} ({})", finding.severity.to_uppercase(), finding.id,
                finding.path, finding.line, finding.message, finding.evidence);
        }
        println!("hashrail scan: {} finding(s)", findings.len());
    }
    Ok(!findings.is_empty())
}

fn changed_files(base: &str) -> Result<Vec<PathBuf>, String> {
    if base.is_empty() || base.starts_with('-') || !base.chars().all(|c| c.is_ascii_alphanumeric() || "/_.-".contains(c)) {
        return Err("--base must be a Git ref name without spaces or option prefixes".into());
    }
    let range = format!("{base}...HEAD");
    let output = Command::new("git")
        .args(["diff", "--name-only", "--diff-filter=ACMR", &range, "--"])
        .output()
        .map_err(|error| format!("run git diff: {error}"))?;
    if !output.status.success() {
        return Err(format!("git diff failed: {}", String::from_utf8_lossy(&output.stderr).trim()));
    }
    let paths: Vec<PathBuf> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|line| !line.is_empty())
        .map(PathBuf::from)
        .collect();
    collect_paths(&paths)
}

fn collect_paths(paths: &[PathBuf]) -> Result<Vec<PathBuf>, String> {
    let mut found = BTreeSet::new();
    for root in paths {
        if !root.exists() {
            continue;
        }
        if root.is_file() {
            found.insert(root.to_path_buf());
            continue;
        }
        for item in WalkDir::new(root).follow_links(false).into_iter().filter_entry(|entry| {
            !matches!(entry.file_name().to_str(), Some(".git" | "node_modules" | "target" | ".venv"))
        }) {
            let item = item.map_err(|error| format!("walk {}: {error}", root.display()))?;
            if item.file_type().is_file() {
                found.insert(item.path().to_path_buf());
            }
        }
    }
    Ok(found.into_iter().collect())
}

fn scan_file(path: &Path, patterns: &Patterns, findings: &mut Vec<Finding>) -> Result<(), String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    if bytes.len() > 2 * 1024 * 1024 || bytes.contains(&0) {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&bytes);
    let display = path.to_string_lossy().replace('\\', "/");
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        for (regex, id, message) in [
            (&patterns.aws_key, "HASHRAIL-AWS-KEY", "Possible AWS access key identifier"),
            (&patterns.github_token, "HASHRAIL-GITHUB-TOKEN", "Possible GitHub access token"),
            (&patterns.slack_token, "HASHRAIL-SLACK-TOKEN", "Possible Slack token"),
            (&patterns.private_key, "HASHRAIL-PRIVATE-KEY", "Private key marker found"),
        ] {
            if let Some(found) = regex.find(line) {
                findings.push(Finding {
                    id, severity: "high", path: display.clone(), line: line_number, message: message.into(),
                    evidence: redact(found.as_str()),
                });
            }
        }
        if let Some(captures) = patterns.assignment.captures(line) {
            if let Some(value) = captures.get(1) {
                if entropy(value.as_str()) >= 3.5 {
                    findings.push(Finding {
                        id: "HASHRAIL-HIGH-ENTROPY", severity: "medium", path: display.clone(), line: line_number,
                        message: "High-entropy value assigned to a credential-like field".into(),
                        evidence: redact(value.as_str()),
                    });
                }
            }
        }
        if display.contains("/.github/workflows/") || display.starts_with(".github/workflows/") {
            if let Some(captures) = patterns.action_use.captures(line) {
                let reference = captures.get(1).map(|value| value.as_str()).unwrap_or("");
                if !reference.starts_with("./") && !reference.starts_with("docker://") {
                    let revision = reference.rsplit_once('@')
                        .map(|(_, rev)| rev.trim_matches('"').trim_matches('\''))
                        .unwrap_or("");
                    if revision.len() != 40 || !revision.chars().all(|c| c.is_ascii_hexdigit()) {
                        findings.push(Finding {
                            id: "HASHRAIL-UNPINNED-ACTION", severity: "medium", path: display.clone(),
                            line: line_number,
                            message: "GitHub Action ref is not pinned to a full commit SHA".into(),
                            evidence: reference.into(),
                        });
                    }
                }
            }
        }
        if display.rsplit('/').next().map(|name| name.eq_ignore_ascii_case("dockerfile")).unwrap_or(false) {
            let trimmed = line.trim();
            if trimmed.to_ascii_uppercase().starts_with("FROM ") {
                let image = trimmed.split_whitespace().skip(1)
                    .find(|part| !part.starts_with("--")).unwrap_or("");
                if !image.contains("@sha256:") {
                    findings.push(Finding {
                        id: "HASHRAIL-MUTABLE-IMAGE", severity: "low", path: display.clone(),
                        line: line_number,
                        message: "Container base image is not pinned by digest".into(),
                        evidence: image.into(),
                    });
                }
            }
        }
    }
    Ok(())
}

fn redact(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 8 {
        return "[redacted]".into();
    }
    format!("{}…{}", chars.iter().take(4).collect::<String>(), chars.iter().rev().take(4).rev().collect::<String>())
}

fn entropy(value: &str) -> f64 {
    let length = value.len() as f64;
    if length == 0.0 {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in value.bytes() {
        counts[byte as usize] += 1;
    }
    counts.iter().filter(|count| **count > 0).map(|count| {
        let probability = *count as f64 / length;
        -probability * probability.log2()
    }).sum()
}
