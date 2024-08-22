use std::{fs, path::Path};

/// parse all nmap output XML files provided
/// and print CSV result to stdout
/// # Panics
/// if any file doesn't exist
/// on any parsing errors (as in missing metadata)
pub fn parse_files(file_names: Vec<String>) {
    let mut non_existent_files = vec![];
    for file_name in &file_names {
        if !Path::new(&file_name).exists() {
            non_existent_files.push(String::from(file_name));
        }
    }
    if !non_existent_files.is_empty() {
        panic!(
            "the following file(s) don't exist: {}",
            non_existent_files.join(", ")
        )
    }

    let mut results: Vec<ScanRecord> = vec![];

    for file_name in file_names {
        eprintln!("processing {}", file_name);
        if let Result::Ok(content) = fs::read_to_string(&file_name) {
            for new_rec in parse_content(content) {
                results.push(new_rec);
            }
        } else {
            panic!("can't read {}", file_name);
        }
    }
    let start_time = results
        .iter()
        .map(|sr| sr.timeframe.start)
        .min()
        .unwrap_or(0);
    let end_time = results.iter().map(|sr| sr.timeframe.end).max().unwrap_or(0);
    println!("start_time,{},end_time,{}", start_time, end_time);
    println!(
        "{}",
        results
            .iter()
            .map(|sr| sr.to_csv())
            .collect::<Vec<String>>()
            .join("\n")
    );
    eprintln!("done, {} opened ports found", results.len());
}

/// parses output of nmap -oX ... into a vector of scan results
/// # Panics
/// on any missing but expected XML node element / attribute required to fill scan result
fn parse_content(content: String) -> Vec<ScanRecord> {
    match roxmltree::Document::parse_with_options(
        &content,
        roxmltree::ParsingOptions {
            allow_dtd: true,
            nodes_limit: 100000,
        },
    ) {
        Result::Ok(doc) => {
            let mut result = vec![];
            for node in doc.descendants() {
                if !node.has_tag_name("host") {
                    continue;
                }
                let start_time: u64 = node
                    .attribute("starttime")
                    .expect("node has no start time")
                    .parse()
                    .expect("can't parse start time into a number");
                let end_time: u64 = node
                    .attribute("endtime")
                    .expect("node has no end time")
                    .parse()
                    .expect("can't parse end time into a number");
                let mut hostnames = node
                    .descendants()
                    .find(|n| n.has_tag_name("hostnames"))
                    .expect("node has no hostnames")
                    .descendants()
                    .filter_map(|h| h.attribute("name").and_then(|n| Some(n.to_string())))
                    .collect::<Vec<String>>();

                hostnames.dedup();

                if hostnames.is_empty() {
                    panic!("hostnames list is empty for: {:?}", hostnames);
                }
                let ip = node
                    .descendants()
                    .find(|n| n.has_tag_name("address") && n.has_attribute("addr"))
                    .expect("host doesn't have address with addr attribute")
                    .attribute("addr")
                    .expect("address doesn't have addr attribute")
                    .to_string();
                for port_node in node
                    .descendants()
                    .find(|n| n.has_tag_name("ports"))
                    .expect("host has no ports")
                    .children()
                {
                    if !port_node.is_element() {
                        continue;
                    }

                    // there is also, at least extraports tag
                    if !port_node.has_tag_name("port") {
                        continue;
                    }

                    let port: u16 = port_node
                        .attribute("portid")
                        .expect(&format!("port {:?} has no id (number)", port_node))
                        .parse()
                        .expect("can't parse port id (number) as integer");
                    if port_node
                        .descendants()
                        .find(|n| n.has_tag_name("state") && n.has_attribute("state"))
                        .expect(&format!(
                            "port {} doesn't have state, can't determine if it's opened or closed",
                            port
                        ))
                        .attribute("state")
                        .expect("port doesn't have state")
                        != "open"
                    {
                        eprintln!("port {} is not opened, skipping", port);
                        continue;
                    }

                    let proto = port_node
                        .attribute("protocol")
                        .expect("port has no protocol name")
                        .to_string();

                    let service = match port_node.descendants().find(|n| n.has_tag_name("service"))
                    {
                        Some(service_node) => service_node
                            .attribute("name")
                            .unwrap_or("<no service name>"),
                        None => "<no service info>",
                    };

                    result.push(ScanRecord {
                        hostnames: hostnames.clone(),
                        ip: ip.clone(),
                        proto,
                        port,
                        service: service.to_string(),
                        timeframe: TimeFrame {
                            start: start_time,
                            end: end_time,
                        },
                    });
                }
            }
            result
        }
        Err(e) => {
            panic!("can't parse an XML document: {}", e);
        }
    }
}

/// represents one record parsed from the scan file
struct ScanRecord {
    hostnames: Vec<String>,
    ip: String,
    proto: String,
    service: String,
    port: u16,
    timeframe: TimeFrame,
}

impl ScanRecord {
    /// convert record to CSV format
    pub fn to_csv(&self) -> String {
        format!(
            "{},{},{},{},{},{},{}",
            self.timeframe.start,
            self.timeframe.end,
            self.ip,
            self.proto,
            self.port,
            self.service,
            self.hostnames.join(","),
        )
    }
}

struct TimeFrame {
    start: u64,
    end: u64,
}
