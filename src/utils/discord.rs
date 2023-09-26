use std::collections::HashMap;
use http::{header, Request, Response, Uri};
use isahc::{AsyncBody, AsyncReadResponseExt, HttpClient, ResponseExt};
use serde_json::{json, Value};
use crate::utils::captcha_solver::{hcaptcha_task_proxyless};
use crate::utils::config::{Config};
use std::time::Duration;
use base64::Engine;
use tokio::time::sleep;
use log::{info, error};
use serde::{Deserialize, Serialize};
use base64::engine::general_purpose;
use regex::Regex;
use url::Url;
use crate::utils::error::MyError;


#[derive(Serialize, Deserialize)]
struct SuperProp {
    os: String,
    browser: String,
    system_locale: String,
    browser_user_agent: String,
    os_version: String,
    referrer: String,
    referring_domain: String,
    search_engine: String,
    referrer_current: String,
    referring_domain_current: String,
    search_engine_current: String,
    release_channel: String,
    client_event_source: String,
}

async fn fingerprint(session: &HttpClient, ua: &str, xsp_res: &str) -> Result<String, isahc::Error> {
    let url = "https://discord.com/api/v9/experiments";
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header("accept", "*/*")
        .header("accept-language", "en-US,en;q=0.5")
        .header("x-discord-locale", "en-US")
        .header("x-debug-options", "bugReporterEnabled")
        .header("user-agent", ua)
        .header("connection", "keep-alive")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-origin")
        .header("te", "trailers")
        .header("x-super-properties", xsp_res)
        .body(())?;
    let mut response = session.send_async(request).await?;

    let text = response.text().await.unwrap_or_default();
    let task_result: Value = serde_json::from_str(&text).unwrap_or_default();

    let mut fingerprints = String::new();
    if let Some(fingerprint) = task_result["fingerprint"].as_str() {
        fingerprints = fingerprint.to_string();
    }
    Ok(fingerprints)
}

async fn generate_x_super_properties(ua: &str) -> String {

    let prop = SuperProp {
        os: "Windows".to_string(),
        browser: "Discord Client".to_string(),
        system_locale: "en-US".to_string(),
        browser_user_agent: (&ua).parse().unwrap(),
        os_version: "".to_string(),
        referrer: "https://www.google.com/".to_string(),
        referring_domain: "www.google.com".to_string(),
        search_engine: "google".to_string(),
        referrer_current: "https://www.google.com/".to_string(),
        referring_domain_current: "www.google.com".parse().unwrap(),
        search_engine_current: "google".parse().unwrap(),
        release_channel: "stable".parse().unwrap(),
        client_event_source: "null".to_string(),
    };

    let json_representation = serde_json::to_string(&prop).unwrap();
    general_purpose::STANDARD.encode(json_representation.as_bytes())
}
async fn get_buildnumber(session: &HttpClient) -> Result<u32, Box<dyn std::error::Error>> {
    let user_agent = "Mozilla/5.0";

    let url = "https://discord.com/app";
    let request = Request::builder()
        .method("GET")
        .uri(url)
        .header("user-agent", user_agent)
        .body(())?;
    let mut response = session.send_async(request).await?;
    let content = response.text().await.unwrap_or_else(|_| "Failed to read response".to_string());

    let asset_regex = Regex::new(r"([a-zA-z0-9]+)\.js")?;
    let captures: Vec<_> = asset_regex.captures_iter(&content).collect();
    let asset = captures.get(captures.len() - 2).unwrap().get(1).unwrap().as_str();

    let asset_url = format!("https://discord.com/assets/{}.js", asset);
    let request0 = Request::builder()
        .method("GET")
        .uri(&asset_url)
        .header("user-agent", user_agent)
        .body(())?;
    let mut response = session.send_async(request0).await?;
    let asset_content = response.text().await.unwrap_or_else(|_| "Failed to read response".to_string());

    let build_info_regex = Regex::new(r#"buildNumber:"[0-9]+"#)?;
    if let Some(build_info_match) = build_info_regex.find(&asset_content) {
        let build_number_str = build_info_match.as_str().split(':').nth(1).unwrap().trim_matches('"');
        let build_number = build_number_str.parse::<u32>()?;
        return Ok(build_number);
    }

    Err("Failed to get build number".into())
}

fn extract_discord_code(content: &str) -> Option<String> {
    let prefixes = ["https://discord.gg/", "https://discord.com/invite/"];

    for prefix in &prefixes {
        if let Some(start) = content.find(prefix) {
            let start = start + prefix.len();
            if let Some(end) = content[start..].find(|c| c == '"' || c == ' ' || c == '\n' || c == '<') {
                return Some(content[start..start+end].to_string());
            }
        }
    }
    None
}


pub async fn connect_discord(
    location_url: &str,
    session: &HttpClient,
    address: &str,
    ds_token: &str,
    ua: &str,
    config: &Config,
) -> Result<String, MyError> {

    let parsed_url = Url::parse(location_url).unwrap();
    let query_params: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();

    let client_id = query_params.get("client_id").cloned().unwrap_or_default();
    let state = query_params.get("state").cloned().unwrap_or_default();
    let redirect_uri = query_params.get("redirect_uri").cloned().unwrap_or_default();

    let xsp_res = generate_x_super_properties(&ua).await;
    // -------------
    let scope = "identify+guilds+guilds.members.read";
    let url1 = format!("https://discord.com/api/v9/oauth2/authorize?client_id={}&response_type=code&redirect_uri={}&scope={}&state={}", client_id, redirect_uri, scope, state );

    let request1 = Request::builder()
        .method("GET")
        .uri(&url1)
        .header("authority", "discord.com")
        .header("authorization", ds_token)
        .header("content-type", "application/json")
        .header("referer", location_url)
        .header("x-super-properties", &xsp_res)
        .body(()).map_err(|err| MyError::ErrorStr(format!("HTTP error: {}", err)))?;
    let _response1 = session.send_async(request1).await?;
    // println!("_response1: {:?}", _response1);
    let mut data: HashMap<String, serde_json::Value> = HashMap::new();
    data.insert("permissions".to_string(), json!("0"));
    data.insert("authorize".to_string(), json!(true));

    let serialized_data = serde_json::to_string(&data).expect("Failed to serialize data");
    // println!("Serialized JSON Data: {}", serialized_data);
    let request2 = Request::builder()
        .method("POST")
        .uri(&url1)
        .header("authority", "discord.com")
        .header("authorization", ds_token)
        .header("content-type", "application/json")
        .header("referer", location_url)
        .header("x-super-properties", &xsp_res)
        .body(serialized_data).map_err(|err| MyError::ErrorStr(format!("HTTP error: {}", err)))?;
    let mut response2 = session.send_async(request2).await?;
    let content = response2.text().await.unwrap_or_else(|_| "Failed to read response".to_string());
    let parsed_content: Result<serde_json::Value, _> = serde_json::from_str(&content);
    match parsed_content {
        Ok(content) => {
            if let Some(location_url) = content["location"].as_str() {
                let _parsed_url = Url::parse(location_url).unwrap();
                let mut loc_url = session.get_async(&location_url.to_string()).await?;
                let content = loc_url.text().await.unwrap_or_else(|_| "Failed to read response".to_string());
                let invite_option = extract_discord_code(&content);
                match invite_option {
                    Some(invite) => {
                        let result = join_server(session, ds_token, &invite, &ua, &config, &xsp_res).await;

                        match result {
                            Ok(_) => {return Ok("Discord connect".to_string())},
                            Err(e) if e.to_string() == "Failed Join after max attempts" => {
                                // println!("Error with discord connection");
                                // return Err(MyError::ErrorStr("Error with discord connection".to_string()))
                                return Ok("Discord Error connect".to_string())
                            },
                            Err(e) => return Ok("Discord Error connect".to_string())
                                // return Err(e),
                        }
                        info!("| {} | Connect DS: {:?} | {} |", address, result, ds_token)
                    }
                    None => {
                        error!("Invite code is not present.");
                    }
                }

            }
        },
        Err(e) => {
            error!("| {} | Error connect DS: Failed to parse JSON content: {}", address, e);
        }
    }

    Ok("Unknown Error.".to_string())
}


pub async fn join_server(session: &HttpClient, token: &str, invite: &str, ua: &str, config: &Config, xsp_res: &str) -> Result<String, MyError> {

    let url = format!("https://discord.com/api/v9/invites/{}", invite);


    let request = Request::builder()
        .method("POST")
        .uri(&url)
        .header("authority", "discord.com")
        .header("authorization", token)
        .header("Content-Type", "application/json")
        .body("{}").map_err(|err| MyError::ErrorStr(format!("HTTP error: {}", err)))?;
    let mut response = session.send_async(request).await?;

    if response.status() != reqwest::StatusCode::OK {

        info!("Connect Discord...");

        let mut captcha_sitekey = String::new();
        let text = response.text().await.unwrap_or_default();
        let task_result: Value = serde_json::from_str(&text).unwrap_or_default();
        // println!("task_result1: {:?}", task_result);
        if let Some(sitekey) = task_result["captcha_sitekey"].as_str() {
            captcha_sitekey = sitekey.to_string();
            // println!("captcha_sitekey: {}", captcha_sitekey);
        }
        let mut captcha_rqtoken = String::new();
        if let Some(rqtoken) = task_result["captcha_rqtoken"].as_str() {
            captcha_rqtoken = rqtoken.to_string();
            // println!("captcha_rqtoken: {}", captcha_rqtoken);
        }
        let mut captcha_rqdata = String::new();
        if let Some(rqdata) = task_result["captcha_rqdata"].as_str() {
            captcha_rqdata = rqdata.to_string();
            // println!("captcha_rqdata: {}", captcha_rqdata);
        }

        if let Some(captcha_key_array) = task_result["captcha_key"].as_array() {
            if let Some(captcha_key) = captcha_key_array.first().and_then(Value::as_str) {
                println!("Captcha : {}", captcha_key);
            }
        }

        let (dcfduid, cfruid, sdcfduid) = extract_discord_cookies(&response).map_err(|err| MyError::ErrorStr(format!("HTTP error: {}", err)))?;


        for attempt in 1..= config.settings.max_retries_connect_server {

            let cap_key = &config.settings.cap_key;
            let website_key = captcha_sitekey.as_str();
            let ws = format!("https://discord.com/api/v9/invites/{}", invite);
            let website_url = ws.as_str();
            let g_recaptcha_response = hcaptcha_task_proxyless(session, website_url, website_key, cap_key, ua, &captcha_rqdata).await?;

            let cookies = format!(
                "__dcfduid={}; __sdcfduid={}; __cfruid={}; locale=en-US",
                dcfduid.clone().unwrap_or_default(),
                sdcfduid.clone().unwrap_or_default(),
                cfruid.clone().unwrap_or_default(),
            );
            // println!("cookies : {:?}", cookies);
            let x_fingerprint_res = fingerprint(&session, &ua, xsp_res).await;
            let x_fingerprint = match x_fingerprint_res {
                Ok(fp) => fp,
                Err(_) => "1153014433115816036.QVUfzwzt-SoWgusrFdol9nVeRfo".to_string(),
            };

            let referer = format!("https://discord.com/invite/{}", invite);


            let mut data2: HashMap<String, serde_json::Value> = HashMap::new();
            // data2.insert("session_id".to_string(), json!(null));
            data2.insert("captcha_key".to_string(), json!(g_recaptcha_response));
            data2.insert("captcha_rqtoken".to_string(), json!(captcha_rqtoken));
            let serialized_data2 = serde_json::to_string(&data2).expect("Failed to serialize data");

            let request1 = Request::builder()
                .method("POST")
                .uri(&url)
                .header("Host", "discord.com")
                .header("Connection", "keep-alive")
                .header("authorization", token)
                .header("Accept-Language", "en-US")
                .header("origin", "https://discord.com")
                .header("referer", referer.to_string())
                .header("sec-ch-ua-mobile", "?0")
                .header("sec-fetch-dest", "empty")
                .header("sec-fetch-mode", "cors")
                .header("sec-fetch-site", "same-origin")
                .header("user-agent", ua)
                .header("X-Debug-Options", "bugReporterEnabled")
                .header("Content-Type", "application/json")
                .header("Cookie", cookies)
                .header("X-Context-Properties", "eyJsb2NhdGlvbiI6IkFjY2VwdEludml0ZVBhZ2UifQ==")
                .header("X-Super-Properties", xsp_res)
                .header("x-fingerprint", &x_fingerprint)
                .version(http::Version::HTTP_2)
                .body(serialized_data2).map_err(|err| MyError::ErrorStr(format!("HTTP error: {}", err)))?;

            let mut response1 = match session.send_async(request1).await {
                Ok(res) => res,
                Err(e) => {
                    println!("Error sending request: {:?}", e);
                    return Err(MyError::ErrorStr(format!("Failed to send request: {}", e)));
                }
            };
            // println!("response1: {:?}", response1);
            // println!("response1 headers: {:?}", response1.headers());
            let text1 = response1.text().await.unwrap_or_default();
            println!("text1: {:?}", text1);
            let task_result1: Value = serde_json::from_str(&text1).unwrap_or_default();
            // println!("task_result2: {}", task_result1);
            if let Some(sitekey) = task_result1["captcha_sitekey"].as_str() {
                captcha_sitekey = sitekey.to_string();
                // println!("captcha_sitekey2: {}", captcha_sitekey);
            }
            // let mut captcha_rqtoken = String::new();
            if let Some(rqtoken) = task_result1["captcha_rqtoken"].as_str() {
                captcha_rqtoken = rqtoken.to_string();
                // println!("captcha_rqtoken2: {}", captcha_rqtoken);
            }

            if response1.status() == reqwest::StatusCode::OK {
                return Ok("Successfully Join 0".to_string());
            } else {
                info!("Attempt {}: Couldn't connect to the channel in Discord, trying again.", attempt);
                sleep(Duration::from_secs(15)).await;

                // If this is the last attempt, return the error
                if attempt == config.settings.max_retries_connect_server {
                    return Ok("Failed Join after max attempts".to_string());
                }
            }
        }
        return Ok("Failed Join after max attempts".to_string());
    } else {
        return Ok("Successfully Join 1".to_string());
    }
}

fn extract_discord_cookies(response: &Response<AsyncBody>) -> Result<(Option<String>, Option<String>, Option<String>), Box<dyn std::error::Error>> {
    let uri = Uri::try_from("https://discord.com/")?;

    if let Some(cookie_jar) = response.cookie_jar() {
        let dcfduid = cookie_jar.get_by_name(&uri, "__dcfduid").map(|c| c.value().to_string());
        let cfruid = cookie_jar.get_by_name(&uri, "__cfruid").map(|c| c.value().to_string());
        let sdcfduid = cookie_jar.get_by_name(&uri, "__sdcfduid").map(|c| c.value().to_string());

        Ok((dcfduid, cfruid, sdcfduid))
    } else {
        Err(Box::new(std::io::Error::new(std::io::ErrorKind::NotFound, "No cookie jar found")))
    }
}
