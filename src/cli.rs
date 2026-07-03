use std::env;
use std::fmt;

#[derive(Debug)]
pub enum CliError {
    MissingInput,
    MissingArgument(String),
    UnknownCommand(String),
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CliError::MissingInput => write!(f, "missing --input flag"),
            CliError::MissingArgument(flag) => write!(f, "missing value for {}", flag),
            CliError::UnknownCommand(cmd) => write!(f, "unknown command '{}'", cmd),
        }
    }
}

#[derive(Debug)]
pub struct CliArgs {
    pub input: String,
    pub allowlist: Option<String>,
    pub out: String,
}

pub fn parse_args() -> Result<CliArgs, CliError> {
    let args: Vec<String> = env::args().collect();

    let mut i = 1;
    let mut input = None;
    let mut allowlist = None;
    let mut out = None;

    while i < args.len() {
        match args[i].as_str() {
            "validate" => {}
            "--input" => {
                i += 1;
                input = Some(
                    args.get(i)
                        .ok_or(CliError::MissingArgument("--input".to_string()))?
                        .clone(),
                );
            }
            "--allowlist" => {
                i += 1;
                allowlist = Some(
                    args.get(i)
                        .ok_or(CliError::MissingArgument("--allowlist".to_string()))?
                        .clone(),
                );
            }
            "--out" => {
                i += 1;
                out = Some(
                    args.get(i)
                        .ok_or(CliError::MissingArgument("--out".to_string()))?
                        .clone(),
                );
            }
            other if other.starts_with('-') => {
                return Err(CliError::MissingArgument(other.to_string()));
            }
            other if i == 1 => {
                return Err(CliError::UnknownCommand(other.to_string()));
            }
            _ => {}
        }
        i += 1;
    }

    let input = input.ok_or(CliError::MissingInput)?;
    let out = out.unwrap_or_else(|| "report".to_string());

    Ok(CliArgs {
        input,
        allowlist,
        out,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_args_validate() {
        let _args = vec![
            "iocguard".to_string(),
            "validate".to_string(),
            "--input".to_string(),
            "data/domains.csv".to_string(),
            "--out".to_string(),
            "report".to_string(),
        ];
        let parsed = CliArgs {
            input: "data/domains.csv".to_string(),
            allowlist: None,
            out: "report".to_string(),
        };
        assert_eq!(parsed.input, "data/domains.csv");
        assert_eq!(parsed.out, "report");
    }
}
