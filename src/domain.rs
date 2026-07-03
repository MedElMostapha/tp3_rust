#[derive(Debug, Clone, PartialEq)]
pub enum DomainStatus {
    Accepted,
    Suspicious,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct DomainRecord {
    pub original: String,
    pub normalized: Option<String>,
    pub source: String,
    pub status: DomainStatus,
    pub reason: String,
}

impl DomainRecord {
    pub fn new(original: String, source: String) -> Self {
        Self {
            original,
            normalized: None,
            source,
            status: DomainStatus::Accepted,
            reason: String::new(),
        }
    }
}

pub fn normalize(domain: &str) -> String {
    let trimmed = domain.trim();
    let lower = trimmed.to_lowercase();
    lower.strip_suffix('.').unwrap_or(&lower).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_example_com() {
        assert_eq!(normalize("Example.COM"), "example.com");
    }

    #[test]
    fn test_normalize_trailing_dot() {
        assert_eq!(normalize("updates.example.org."), "updates.example.org");
    }

    #[test]
    fn test_normalize_spaces() {
        assert_eq!(normalize("  Example.COM  "), "example.com");
    }
}
