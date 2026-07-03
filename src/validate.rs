use crate::domain::{DomainRecord, DomainStatus, normalize};

const SUSPICIOUS_TLDS: &[&str] = &["zip", "mov", "top", "xyz", "tk"];
const SUSPICIOUS_KEYWORDS: &[&str] = &["login", "verify", "secure", "update", "paypa1"];

#[derive(Debug)]
pub struct ValidationResult {
    pub records: Vec<DomainRecord>,
    pub processed: usize,
    pub valid_count: usize,
    pub invalid_count: usize,
    pub allowlisted_count: usize,
    pub suspicious_count: usize,
}

fn is_valid_domain(domain: &str) -> Result<(), String> {
    if domain.is_empty() {
        return Err("domain is empty".to_string());
    }
    if !domain.contains('.') {
        return Err("domain has no dot".to_string());
    }
    if domain.len() > 253 {
        return Err("domain length exceeds 253 characters".to_string());
    }
    if domain.contains("..") {
        return Err("domain contains consecutive dots".to_string());
    }

    for ch in domain.chars() {
        if !ch.is_ascii_lowercase() && !ch.is_ascii_digit() && ch != '.' && ch != '-' {
            return Err(format!("invalid character '{}' in domain", ch));
        }
    }

    let labels: Vec<&str> = domain.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            return Err("domain contains an empty label".to_string());
        }
        if label.len() > 63 {
            return Err(format!("label '{}' exceeds 63 characters", label));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("label '{}' starts or ends with a hyphen", label));
        }
    }

    Ok(())
}

fn is_suspicious_domain(domain: &str) -> bool {
    if domain.starts_with("xn--") {
        return true;
    }

    if let Some(tld) = domain.rsplit('.').next()
        && SUSPICIOUS_TLDS.contains(&tld)
    {
        return true;
    }

    let lower = domain.to_lowercase();
    for kw in SUSPICIOUS_KEYWORDS {
        if lower.contains(kw) {
            return true;
        }
    }

    if domain.chars().filter(|&c| c == '-').count() >= 3 {
        return true;
    }

    false
}

fn parse_csv_line(line: &str) -> Result<(String, String), String> {
    let line = line.trim();
    if line.is_empty() {
        return Err("empty line".to_string());
    }

    let mut parts = line.splitn(2, ',');
    let domain = parts.next().ok_or("missing domain")?.trim().to_string();
    let source = parts.next().ok_or("missing source")?.trim().to_string();

    if domain.is_empty() {
        return Err("empty domain in CSV line".to_string());
    }

    Ok((domain, source))
}

pub fn process_input(csv_content: &str, allowlist: &[String]) -> ValidationResult {
    let mut records = Vec::new();
    let mut processed = 0;
    let mut valid_count = 0;
    let mut invalid_count = 0;
    let mut allowlisted_count = 0;
    let mut suspicious_count = 0;

    for line in csv_content.lines().skip(1) {
        if line.trim().is_empty() {
            continue;
        }

        processed += 1;

        let (domain, source) = match parse_csv_line(line) {
            Ok(pair) => pair,
            Err(e) => {
                records.push(DomainRecord {
                    original: line.to_string(),
                    normalized: None,
                    source: String::new(),
                    status: DomainStatus::Rejected,
                    reason: format!("malformed CSV line: {}", e),
                });
                invalid_count += 1;
                continue;
            }
        };

        let normalized = normalize(&domain);

        match is_valid_domain(&normalized) {
            Err(e) => {
                records.push(DomainRecord {
                    original: domain,
                    normalized: Some(normalized),
                    source,
                    status: DomainStatus::Rejected,
                    reason: e,
                });
                invalid_count += 1;
            }
            Ok(()) => {
                let is_allowlisted = allowlist.iter().any(|a| a == &normalized);

                if is_allowlisted {
                    allowlisted_count += 1;
                    records.push(DomainRecord {
                        original: domain,
                        normalized: Some(normalized),
                        source,
                        status: DomainStatus::Accepted,
                        reason: "allowlisted".to_string(),
                    });
                    valid_count += 1;
                } else if is_suspicious_domain(&normalized) {
                    suspicious_count += 1;
                    records.push(DomainRecord {
                        original: domain,
                        normalized: Some(normalized),
                        source,
                        status: DomainStatus::Suspicious,
                        reason: "suspicious pattern detected".to_string(),
                    });
                    valid_count += 1;
                } else {
                    records.push(DomainRecord {
                        original: domain,
                        normalized: Some(normalized),
                        source,
                        status: DomainStatus::Accepted,
                        reason: String::new(),
                    });
                    valid_count += 1;
                }
            }
        }
    }

    ValidationResult {
        records,
        processed,
        valid_count,
        invalid_count,
        allowlisted_count,
        suspicious_count,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reject_consecutive_dots() {
        assert!(is_valid_domain("bad..domain").is_err());
    }

    #[test]
    fn test_reject_leading_hyphen() {
        assert!(is_valid_domain("-malformed.com").is_err());
    }

    #[test]
    fn test_reject_trailing_hyphen() {
        assert!(is_valid_domain("malformed-.com").is_err());
    }

    #[test]
    fn test_reject_no_dot() {
        assert!(is_valid_domain("nodomain").is_err());
    }

    #[test]
    fn test_reject_empty() {
        assert!(is_valid_domain("").is_err());
    }

    #[test]
    fn test_valid_accepts() {
        assert!(is_valid_domain("example.com").is_ok());
    }

    #[test]
    fn test_valid_accepts_hyphenated() {
        assert!(is_valid_domain("my-example.com").is_ok());
    }

    #[test]
    fn test_suspicious_xn() {
        assert!(is_suspicious_domain("xn--phishing-test.com"));
    }

    #[test]
    fn test_suspicious_tld_xyz() {
        assert!(is_suspicious_domain("paypa1-login.xyz"));
    }

    #[test]
    fn test_suspicious_keyword() {
        assert!(is_suspicious_domain("login-example.com"));
    }

    #[test]
    fn test_suspicious_three_hyphens() {
        assert!(is_suspicious_domain("a-b-c-test.com"));
    }

    #[test]
    fn test_not_suspicious_normal() {
        assert!(!is_suspicious_domain("example.com"));
    }

    #[test]
    fn test_allowlisted_not_suspicious() {
        let csv = "domain,source\nxn--phishing-test.com,email_gateway\n";
        let allowlist = vec!["xn--phishing-test.com".to_string()];
        let result = process_input(csv, &allowlist);
        assert_eq!(result.allowlisted_count, 1);
        assert_eq!(result.suspicious_count, 0);
    }

    #[test]
    fn test_malformed_csv_line() {
        let csv = "domain,source\n";
        let allowlist = vec![];
        let result = process_input(csv, &allowlist);
        assert_eq!(result.processed, 0);
    }

    #[test]
    fn test_paypal1_login_suspicious() {
        let csv = "domain,source\npaypa1-login.xyz,email_gateway\n";
        let allowlist = vec![];
        let result = process_input(csv, &allowlist);
        assert_eq!(result.suspicious_count, 1);
        assert_eq!(result.valid_count, 1);
    }

    #[test]
    fn test_full_processing() {
        let csv = "domain,source\nExample.COM,manual\nbad..domain,proxy_log\n";
        let allowlist = vec!["example.com".to_string()];
        let result = process_input(csv, &allowlist);
        assert_eq!(result.processed, 2);
        assert_eq!(result.allowlisted_count, 1);
        assert_eq!(result.invalid_count, 1);
    }

    #[test]
    fn test_reject_long_label() {
        let long = "a".repeat(64) + ".com";
        assert!(is_valid_domain(&long).is_err());
    }

    #[test]
    fn test_reject_long_domain() {
        let long = "a".repeat(254);
        assert!(is_valid_domain(&long).is_err());
    }

    #[test]
    fn test_reject_invalid_char() {
        assert!(is_valid_domain("exam ple.com").is_err());
    }
}
