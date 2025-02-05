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

const IN_FILE: &str = "/home/spirillen/Downloads/newIssues.csv";
const OUT_FILE: &str = "/home/spirillen/Downloads/issues.csv";
const MAX_RETRIES: usize = 3;
const RETRY_DELAY: Duration = Duration::from_secs(5);
const REPO: &str = "mypdns/matrix";

fn main() {
    // Load GITHUB_TOKEN from config file
    let home_dir = env::var("HOME").expect("Could not find home directory");
    let config_path = format!("{}/.config/myPrivacyDNS/config.user.json", home_dir);
    let github_token = get_github_token(&config_path).expect("Failed to retrieve GITHUB_TOKEN");

    // Create output file with header if it doesn't exist
    let mut writer = WriterBuilder::new().from_path(OUT_FILE).unwrap();
    writer.write_record(&["Title", "Issue link"]).unwrap();

    let mut reader = ReaderBuilder::new().from_path(IN_FILE).unwrap();
    let records: Vec<_> = reader.records().collect();

    // Create a temporary file for the screenshot
    let screenshot_file = std::env::temp_dir().join("screenshot.png");

    let (tx, rx) = channel();

    for record in records {
        let record = record.unwrap();
        let line = record.get(0).unwrap().to_string();
        let tx = tx.clone();

        let github_token = github_token.clone();
        thread::spawn(move || {
            let d_records = std::process::Command::new("dig")
                .arg("+short")
                .arg("+tls")
                .arg("@91.239.100.100")
                .arg("-t")
                .arg("NS")
                .arg(&line)
                .output()
                .expect("Failed to execute dig")
                .stdout;
            let d_records = String::from_utf8(d_records).unwrap();

            let known_issues = Client::new()
                .get(&format!(
                    "https://api.github.com/search/issues?q={line}+type:issue&sort=indexed"
                ))
                .header("Accept", "application/vnd.github.text-match+json")
                .bearer_auth(&github_token)
                .send()
                .unwrap()
                .text()
                .unwrap();

            let existing_issue = Client::new()
                .get(&format!(
                    "https://api.github.com/search/issues?q={line}%20in:title%20type:issue%20repo:{REPO}"
                ))
                .header("Accept", "application/vnd.github.text-match+json")
                .bearer_auth(&github_token)
                .send()
                .unwrap()
                .text()
                .unwrap();

            let screenshot_result = capture_screenshot(&line, &screenshot_file);
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
                {}\
                \n\n</details>\n\n\
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

            tx.send((line, body, existing_issue)).unwrap();
        });
    }

    drop(tx);

    let mut writer = WriterBuilder::new().from_path(OUT_FILE).unwrap();

    for (line, body, existing_issue) in rx {
        if !existing_issue.is_empty() {
            let issue_url = serde_json::from_str::<Value>(&existing_issue)
                .unwrap()["url"]
                .as_str()
                .unwrap()
                .to_string();
            Client::new()
                .post(&format!("{issue_url}/comments"))
                .header("Authorization", format!("Bearer {}", github_token))
                .header("Accept", "application/vnd.github+json")
                .json(&serde_json::json!({ "body": body }))
                .send()
                .unwrap();
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
                let response = Client::new()
                    .post(&format!("https://api.github.com/repos/{REPO}/issues"))
                    .header("Accept", "application/vnd.github+json")
                    .header("Authorization", format!("Bearer {}", github_token))
                    .json(&json_body)
                    .send()
                    .unwrap();

                if response.status().is_success() {
                    let response_json: Value = response.json().unwrap();
                    let title = response_json["title"].as_str().unwrap().to_string();
                    let html_url = response_json["html_url"].as_str().unwrap().to_string();
                    writer.write_record(&[title, html_url]).unwrap();
                    break;
                } else {
                    thread::sleep(RETRY_DELAY);
                }
            }
        }
    }

    std::fs::remove_file(IN_FILE).unwrap();
}

fn capture_screenshot(url: &str, file_path: &std::path::Path) -> Result<(), Box<dyn std::error::Error>> {
    let options = LaunchOptionsBuilder::default()
        .headless(true)
        .build()
        .unwrap();
    let browser = Browser::new(options)?;
    let tab = browser.new_tab()?;
    tab.navigate_to(url)?;
    tab.wait_until_navigated()?;
    let png_data = tab.capture_screenshot(headless_chrome::protocol::cdp::Page::CaptureScreenshotFormatOption::Png, None)?;
    std::fs::write(file_path, png_data)?;
    Ok(())
}

fn upload_screenshot(screenshot_file: &std::path::Path, github_token: &str) -> Option<String> {
    for _ in 0..MAX_RETRIES {
        let upload_response = Client::new()
            .put(&format!(
                "https://uploads.github.com/repos/{REPO}/contents/screenshots/{}?ref=master",
                screenshot_file.file_name().unwrap().to_str().unwrap()
            ))
            .header("Authorization", format!("Bearer {}", github_token))
            .header("Content-Type", "application/octet-stream")
            .body(std::fs::read(screenshot_file).unwrap())
            .send()
            .unwrap();

        if upload_response.status().is_success() {
            let response_json: Value = upload_response.json().unwrap();
            return Some(response_json["content"]["download_url"]
                .as_str()
                .unwrap()
                .to_string());
        } else {
            thread::sleep(RETRY_DELAY);
        }
    }
    None
}

fn get_github_token(config_path: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut file = File::open(config_path)?;
    let mut contents = String::new();
    file.read_to_string(&mut contents)?;
    let json: Value = serde_json::from_str(&contents)?;
    let token = json["GITHUB_TOKEN"].as_str().ok_or("GITHUB_TOKEN not found")?.to_string();
    Ok(token)
}