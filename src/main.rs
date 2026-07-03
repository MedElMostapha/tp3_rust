use std::fs;
use std::io::Read;
use std::process;

use iocguard::cli;
use iocguard::report;
use iocguard::validate;

fn read_file(path: &str) -> Result<String, String> {
    let mut file = fs::File::open(path).map_err(|e| format!("cannot open '{}': {}", path, e))?;
    let mut content = String::new();
    file.read_to_string(&mut content)
        .map_err(|e| format!("cannot read '{}': {}", path, e))?;
    Ok(content)
}

fn read_allowlist(path: Option<&str>) -> Result<Vec<String>, String> {
    match path {
        Some(p) => {
            let content = read_file(p)?;
            Ok(content.lines().map(|l| l.trim().to_lowercase()).collect())
        }
        None => Ok(Vec::new()),
    }
}

fn main() {
    let args = match cli::parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let csv_content = match read_file(&args.input) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let allowlist = match read_allowlist(args.allowlist.as_deref()) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    let result = validate::process_input(&csv_content, &allowlist);

    if let Err(e) = report::write_report(&result, &args.out) {
        eprintln!("Error: cannot write report: {}", e);
        process::exit(1);
    }

    report::print_summary(&result, &args.out);
}
