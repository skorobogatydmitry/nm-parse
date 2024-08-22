use std::{env, process};

use nm_parse;

const USAGE: &str = r#"
Usage: nm-parse FILE_1 FILE_2 ... FILE_N <--help>
  --help                    - print this usage
  FILE_1 FILE_2 ... FILE_N  - files to parse

A tool to parse multiple nmap scan results in XML format into a single CSV report of opened ports.
The tool prints parsing logs to stderr and parsing results to stdout,
so logs and results could be stored as files this way:
    nm-parse data.xml 2>nm-parse.log 1>nm-parse.csv
Multiple files (or directories) could be supplied with shell expansion:
    nm-parse reports/*.xml
"#;

fn main() {
    let mut args: Vec<String> = env::args().collect();
    if args.len() < 2 || args.contains(&String::from("--help")) {
        println!("{}", USAGE);
        process::exit(1);
    }
    nm_parse::parse_files(args.drain(1..).collect());
}
