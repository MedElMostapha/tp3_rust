use std::fs;
use std::io::{self, Write};
use std::path::Path;

use crate::domain::DomainStatus;
use crate::validate::ValidationResult;

fn create_dir(dir: &str) -> io::Result<()> {
    let path = Path::new(dir);
    if path.exists() {
        if path.is_dir() {
            fs::remove_dir_all(path)?;
        } else {
            fs::remove_file(path)?;
        }
    }
    fs::create_dir_all(path)
}

fn write_csv(path: &str, headers: &str, rows: &[String]) -> io::Result<()> {
    let mut file = fs::File::create(path)?;
    writeln!(file, "{}", headers)?;
    for row in rows {
        writeln!(file, "{}", row)?;
    }
    Ok(())
}

fn escape_csv(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

pub fn write_report(result: &ValidationResult, out_dir: &str) -> io::Result<()> {
    create_dir(out_dir)?;

    let mut accepted_rows = Vec::new();
    let mut suspicious_rows = Vec::new();
    let mut rejected_rows = Vec::new();

    for record in &result.records {
        match record.status {
            DomainStatus::Accepted => {
                let normalized = record.normalized.as_deref().unwrap_or(&record.original);
                let reason = if record.reason.is_empty() {
                    "valid".to_string()
                } else {
                    record.reason.clone()
                };
                accepted_rows.push(format!(
                    "{},{},{},{}",
                    escape_csv(normalized),
                    escape_csv(&record.source),
                    "accepted",
                    escape_csv(&reason)
                ));
            }
            DomainStatus::Suspicious => {
                let normalized = record.normalized.as_deref().unwrap_or(&record.original);
                suspicious_rows.push(format!(
                    "{},{},{},{}",
                    escape_csv(normalized),
                    escape_csv(&record.source),
                    "suspicious",
                    escape_csv(&record.reason)
                ));
            }
            DomainStatus::Rejected => {
                rejected_rows.push(format!(
                    "{},{},{},{}",
                    escape_csv(&record.original),
                    escape_csv(&record.source),
                    "rejected",
                    escape_csv(&record.reason)
                ));
            }
        }
    }

    let accepted_path = Path::new(out_dir).join("accepted.csv");
    let suspicious_path = Path::new(out_dir).join("suspicious.csv");
    let rejected_path = Path::new(out_dir).join("rejected.csv");
    let summary_path = Path::new(out_dir).join("summary.txt");

    write_csv(
        accepted_path.to_str().unwrap(),
        "normalized_domain,source,status,reason",
        &accepted_rows,
    )?;

    write_csv(
        suspicious_path.to_str().unwrap(),
        "normalized_domain,source,status,reason",
        &suspicious_rows,
    )?;

    write_csv(
        rejected_path.to_str().unwrap(),
        "original_value,source,status,reason",
        &rejected_rows,
    )?;

    let mut summary = fs::File::create(summary_path)?;
    writeln!(summary, "IOCGuard Report Summary")?;
    writeln!(summary, "{}", "=".repeat(30))?;
    writeln!(summary, "Total lines processed: {}", result.processed)?;
    writeln!(summary, "Valid domains:       {}", result.valid_count)?;
    writeln!(summary, "Invalid domains:     {}", result.invalid_count)?;
    writeln!(summary, "Allowlisted domains: {}", result.allowlisted_count)?;
    writeln!(summary, "Suspicious domains:  {}", result.suspicious_count)?;

    Ok(())
}

pub fn print_summary(result: &ValidationResult, out_dir: &str) {
    println!("IOCGuard report");
    println!("Processed lines  : {}", result.processed);
    println!("Valid domains    : {}", result.valid_count);
    println!("Invalid domains  : {}", result.invalid_count);
    println!("Allowlisted domains: {}", result.allowlisted_count);
    println!("Suspicious domains : {}", result.suspicious_count);
    println!("Report directory : {}", out_dir);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_escape_csv_simple() {
        assert_eq!(escape_csv("hello"), "hello");
    }

    #[test]
    fn test_escape_csv_with_comma() {
        assert_eq!(escape_csv("he,llo"), "\"he,llo\"");
    }

    #[test]
    fn test_escape_csv_with_quotes() {
        assert_eq!(escape_csv("he\"llo"), "\"he\"\"llo\"");
    }
}
