use clap::{App, Arg};
use csv::ReaderBuilder;
use csv::WriterBuilder;
use headless_chrome::{Browser, LaunchOptionsBuilder};
use reqwest::blocking::Client;
use serde_json::Value;
use std::fs::File;
use std::io::Read;
use std::sync::mpsc::channel;
use std::thread;
use std::time::Duration;
use std::env;
use std::path::PathBuf;
use regex::Regex;

const MAX_RETRIES: usize = 3;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const REPO: &str = "mypdns/matrix";

fn main() {
    let matches = App::new("API_GH_manual")
        .version("0.1.0")
        .author("Spirillen <spirillen@danwin1210.de>")
        .about("A program to take screenshots of websites and upload them to GitHub issues.")
        .arg(Arg::new("infile")
            .short('i')
            .long("infile")
            .value_name("FILE")
            .help("Sets the input file")
            .takes_value(true))
        .arg(Arg::new("outfile")
            .short('o')
            .long("outfile")
            .value_name("FILE")
            .help("Sets the output file")
            .takes_value(true))
        .arg(Arg::new("version")
            .short('v')
            .long("version")
            .help("Prints version information"))
        .arg(Arg::new("help")
            .short('h')
            .long("help")
            .help("Prints help information"))
        .get_matches();

    let in_file = matches.value_of("infile").unwrap_or("data/newIssues.csv");
    let out_file = matches.value_of("outfile").unwrap_or("data/issues.csv");

    // Load GITHUB_TOKEN from config file
    let home_dir = env::var("HOME").expect("Could not find home directory");
    let config_path = format!("{}/.config/myPrivacyDNS/config.user.json", home_dir);
    let github_token = match get_github_token(&config_path) {
        Ok(token) => token,
        Err(e) => {
            eprintln!("Failed to retrieve GITHUB_TOKEN: {}", e);
            return;
        }
    };

    // Create output file with header if it doesn't exist
    let mut writer = match WriterBuilder::new().from_path(&out_file) {
        Ok(writer) => writer,
        Err(_) => {
            eprintln!("Could not create output file: {}", out_file);
            std::process::exit(1);
        }
    };
    writer.write_record(&["Title", "Issue link"]).expect("Failed to write header");

    let mut reader = match ReaderBuilder::new().from_path(&in_file) {
        Ok(reader) => reader,
        Err(_) => {
            eprintln!("Could not open input file: {}", in_file);
            std::process::exit(1);
        }
    };
    let records: Vec<_> = reader.records().collect();

    // Create a temporary file for the screenshot
    let screenshot_file = std::env::temp_dir().join("screenshot.png");

    let (tx, rx) = channel();

    for record in records {
        let record = match record {
            Ok(rec) => rec,
            Err(e) => {
                eprintln!("Failed to read record: {}", e);
                continue;
            }
        };
        let line = match record.get(0) {
            Some(line) => line.to_string(),
            None => {
                eprintln!("Failed to get line from record");
                continue;
            }
        };
        let tx = tx.clone();

        let github_token = github_token.clone();
        let screenshot_file = screenshot_file.clone(); // Clone the screenshot_file to avoid moving the value
        thread::spawn(move || {
            let d_records = match std::process::Command::new("dig")
                .arg("+short")
                .arg("+tls")
                .arg("@91.239.100.100")
                .arg("-t")
                .arg("NS")
                .arg(&line)
                .output()
            {
                Ok(output) => String::from_utf8(output.stdout).expect("Failed to convert output to string"),
                Err(e) => {
                    eprintln!("Failed to execute dig: {}", e);
                    return;
                }
            };

            let known_issues = match Client::new()
                .get(&format!(
                    "https://api.github.com/search/issues?q={line}+type:issue&sort=indexed"
                ))
                .header("Accept", "application/vnd.github.text-match+json")
                .send()
            {
                Ok(resp) => match resp.text() {
                    Ok(text) => text,
                    Err(e) => {
                        eprintln!("Failed to get response text: {}", e);
                        return;
                    }
                },
                Err(e) => {
                    eprintln!("Failed to send request: {}", e);
                    return;
                }
            };

            let existing_issue = match Client::new()
                .get(&format!(
                    "https://api.github.com/search/issues?q={line}%20in:title%20type:issue%20repo:{REPO}"
                ))
                .header("Accept", "application/vnd.github.text-match+json")
                .header("User-Agent", "MyNewApp")
                .bearer_auth(&github_token)
                .send()
            {
                Ok(resp) => match resp.text() {
                    Ok(text) => text,
                    Err(e) => {
                        eprintln!("Failed to get response text: {}", e);
                        return;
                    }
                },
                Err(e) => {
                    eprintln!("Failed to send request: {}", e);
                    return;
                }
            };

            // Validate and sanitize the line input before using it in path value creation
            let sanitized_line = sanitize_input(&line);

            let screenshot_result = capture_screenshot(&sanitized_line, &screenshot_file);
            let download_url = match screenshot_result {
                Ok(_) => upload_screenshot(&screenshot_file, &github_token),
                Err(_) => None,
            };

            let body = format!(
                "### Comments\n\n\
                Previously committed an approved domain, used for serving Porn contents\n\n\
                ### Domain\n\n\
                ```CSV\n{line}\n```\n\n\
                ### Wildcard domain records\n\n\
                ```CSV\n{line}|adult\n```\n\n\
                ### Sub-Domain records\n\n\
                ```CSV\nnull\n```\n\n\
                ### Hosts (RFC:952) specific records, not used by DNS RPZ firewalls\n\n\
                ```CSV\nnull\n```\n\n\
                ### Safe Search records\n\n\
                ```CSV\nnull\n```\n\n\
                ### Screenshots\n\n\
                <details><summary>Screenshot (click to expand)</summary>\n\n\
                {}\n\n</details>\n\n\
                ### Links to external sources\n\n\
                {}\n\n\
                ### Name servers\n\n\
                ```text\n{}\n```\n\n\
                ### logs from uBlock Origin\n\n\
                N/A",
                download_url
                    .map(|url| format!("![Screenshot of {line} taken by My Privacy DNS ©]({url})"))
                    .unwrap_or_else(|| "N/A".to_string()),
                known_issues,
                d_records
            );

            if !existing_issue.is_empty() {
                if let Err(e) = tx.send((line, body, existing_issue)) {
                    eprintln!("Failed to send data: {}", e);
                }
            } else {
                eprintln!("Error: existing_issue is empty");
            }
        });
    }

    drop(tx);

    let mut writer = match WriterBuilder::new().from_path(out_file) {
        Ok(writer) => writer,
        Err(e) => {
            eprintln!("Failed to create writer: {}", e);
            return;
        }
    };

    for (line, body, existing_issue) in rx {
        handle_issue(line, body, existing_issue, &github_token, &mut writer);
    }
}

fn handle_issue(line: String, body: String, existing_issue: String, github_token: &str, writer: &mut csv::Writer<std::fs::File>) {
    if !existing_issue.is_empty() {
        let issue_url = match serde_json::from_str::<Value>(&existing_issue) {
            Ok(json) => match json["url"].as_str() {
                Some(url) => url.to_string(),
                None => {
                    eprintln!("Failed to get URL from json: {}", existing_issue);
                    return;
                }
            },
            Err(e) => {
                eprintln!("Failed to parse existing issue JSON: {}, Error: {}", existing_issue, e);
                return;
            }
        };
        if let Err(e) = Client::new()
            .post(&format!("{issue_url}/comments"))
            .bearer_auth(&github_token)
            .header("Accept", "application/vnd.github+json")
            .json(&serde_json::json!({ "body": body }))
            .send()
        {
            eprintln!("Failed to post comment: {}", e);
        }
    } else {
        let json_body = serde_json::json!({
            "title": line,
            "body": body,
            "labels": ["NSFW Adult Material"],
            "milestone": 4,
            "state": "closed",
            "state_reason": "completed"
        });

        for _ in 0..MAX_RETRIES {
            match Client::new()
                .post(&format!("https://api.github.com/repos/{REPO}/issues"))
                .bearer_auth(&github_token)
                .header("Accept", "application/vnd.github+json")
                .json(&json_body)
                .send()
            {
                Ok(response) => {
                    if response.status().is_success() {
                        match response.json::<Value>() {
                            Ok(response_json) => {
                                let title = match response_json["title"].as_str() {
                                    Some(title) => title.to_string(),
                                    None => {
                                        eprintln!("Failed to get title from response JSON: {}", response_json);
                                        continue;
                                    }
                                };
                                let html_url = match response_json["html_url"].as_str() {
                                    Some(url) => url.to_string(),
                                    None => {
                                        eprintln!("Failed to get html_url from response JSON: {}", response_json);
                                        continue;
                                    }
                                };
                                if let Err(e) = writer.write_record(&[title, html_url]) {
                                    eprintln!("Failed to write record: {}", e);
                                }
                                break;
                            }
                            Err(e) => {
                                let response_text = response.text().unwrap_or_else(|_| "Error retrieving response text".to_string());
                                eprintln!("Failed to parse response JSON: {}, Error: {}", response_text, e);
                                continue;
                            }
                        }
                    } else {
                        thread::sleep(RETRY_DELAY);
                    }
                }
                Err(e) => {
                    eprintln!("Failed to send request: {}", e);
                    thread::sleep(RETRY_DELAY);
                }
            }
        }
    }
}

fn capture_screenshot(url: &str, file_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    let options = LaunchOptionsBuilder::default()
        .headless(true)
        .build()?;
    let browser = Browser::new(options)?;
    let tab = browser.new_tab()?;
    tab.navigate_to(url)?;
    tab.wait_until_navigated()?;
    let png_data = tab.capture_screenshot(
        headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png,
        None, // No viewport specified
        None, // No quality specified
        true // Capture from surface
    )?;
    std::fs::write(file_path, png_data)?;
    Ok(())
}

fn upload_screenshot(screenshot_file: &PathBuf, github_token: &str) -> Option<String> {
    for _ in 0..MAX_RETRIES {
        match Client::new()
            .put(&format!(
                "https://uploads.github.com/repos/{REPO}/contents/screenshots/{}?ref=master",
                screenshot_file.file_name()?.to_str()?
            ))
            .header("Authorization", format!("Bearer {}", github_token))
            .header("Content-Type", "application/octet-stream")
            .body(std::fs::read(screenshot_file).ok()?)
            .send()
        {
            Ok(upload_response) => {
                if upload_response.status().is_success() {
                    return upload_response.json::<Value>().ok()?.get("content")?.get("download_url")?.as_str().map(String::from);
                }
            }
            Err(e) => {
                eprintln!("Failed to upload screenshot: {}", e);
                thread::sleep(RETRY_DELAY);
            }
        }
    }
    None
}

fn get_github_token(config_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    if contents.trim().is_empty() {
        return Err("Empty JSON content".into());
    }
    let json: Value = serde_json::from_str(&contents)?;
    let token = json["GITHUB_TOKEN"]
        .as_str()
        .ok_or("GITHUB_TOKEN not found")?
        .to_string();
    Ok(token)
}

fn sanitize_input(input: &str) -> String {
    let re = Regex::new(r"[^a-zA-Z0-9]").unwrap();
    re.replace_all(input, "_").to_string()
}