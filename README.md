# NMap's output parser

It's a small tool to parse multiple [NMap](https://nmap.org/) scan results into a single CSV of opened ports.  
All scan results are expected to have XML format (were captured with `-oX file.xml`).  
Check `nm-parse --help` for usage.

## Build

`cargo build --release ; target/release/nm-parse --help`
