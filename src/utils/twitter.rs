use std::collections::HashMap;
use http::{header, Request};
use isahc::{AsyncReadResponseExt, HttpClient};
use serde_json::{json, Value};
use url::Url;

pub async fn connect_oauth2 (
    session: &HttpClient,
    url: &str,
    auth_token: &str,
    ct0: &str,
    ua: &str
) -> Result<String, isahc::Error> {

    let parsed_url = Url::parse(url).unwrap();
    let query_params: HashMap<String, String> = parsed_url.query_pairs().into_owned().collect();

    let client_id = query_params.get("client_id").cloned().unwrap_or_default();
    let code_challenge = query_params.get("code_challenge").cloned().unwrap_or_default();
    let state = query_params.get("state").cloned().unwrap_or_default();
    let redirect_uri = query_params.get("redirect_uri").cloned().unwrap_or_default();
    let cookies_string = format!(
        "auth_token={}; ct0={}; lang=en",
        auth_token,
        ct0
    );

    let tw_url = format!("https://twitter.com/i/api/2/oauth2/authorize?client_id={}&code_challenge={}&code_challenge_method=plain&redirect_uri={}&response_type=code&scope=tweet.read+tweet.write+users.read+follows.read+follows.write+offline.access&state={}", client_id, code_challenge, redirect_uri, state);
    let referer = format!("https://twitter.com/i/oauth2/authorize?client_id={}&code_challenge={}&code_challenge_method=plain&redirect_uri={}&response_type=code&scope=tweet.read+tweet.write+users.read+follows.read+follows.write+offline.access&state={}", client_id, code_challenge, redirect_uri, state);
    let request_tw = Request::builder()
        .method("GET")
        .uri(tw_url)
        .header("authority", "twitter.com")
        .header("accept", "*/*")
        .header("accept-language", "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7")
        .header("authorization", "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA")
        .header("origin", "https://twitter.com")
        .header("referer", referer)
        .header(header::COOKIE, &cookies_string)
        .header("sec-ch-ua", "\"Google Chrome\";v=\"117\", \"Not;A=Brand\";v=\"8\", \"Chromium\";v=\"117\"")
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", "\"Windows\"")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-origin")
        .header("user-agent", ua)
        .header("x-csrf-token", ct0)
        .header("x-twitter-active-user", "yes")
        .header("x-twitter-auth-type", "OAuth2Session")
        .header("x-twitter-client-language", "en")
        .body(())?;
    // println!("request_tw: {:?}", request_tw);
    let mut response_tw = session.send_async(request_tw).await?;

    let text = response_tw.text().await.unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text).unwrap_or_default();

    // -------------------

    if let Some(auth_code) = parsed["auth_code"].as_str() {
        // println!("auth_code: {}", auth_code);
        let tw_url = format!("https://twitter.com/i/api/2/oauth2/authorize?client_id={}&code_challenge={}&code_challenge_method=plain&redirect_uri={}&response_type=code&scope=tweet.read+tweet.write+users.read+follows.read+follows.write+offline.access&state={}", client_id, code_challenge, redirect_uri, state);
        let referer = format!("https://twitter.com/i/oauth2/authorize?client_id={}&code_challenge={}&code_challenge_method=plain&redirect_uri={}&response_type=code&scope=tweet.read+tweet.write+users.read+follows.read+follows.write+offline.access&state={}", client_id, code_challenge, redirect_uri, state);
        let mut data: HashMap<String, serde_json::Value> = HashMap::new();
        data.insert("approval".to_string(), json!("true"));
        data.insert("code".to_string(), json!(auth_code));
        let serialized_data = serde_json::to_string(&data).expect("Failed to serialize data");
        // println!("data: {}", &serialized_data);
        let request_tw = Request::builder()
            .method("POST")
            .uri(tw_url)
            .header("Content-Type", "application/json")
            .header("authorization", "Bearer AAAAAAAAAAAAAAAAAAAAANRILgAAAAAAnNwIzUejRCOuH5E6I8xnZz4puTs%3D1Zv7ttfk8LF81IUq16cHjhLTvJu4FA33AGWWjCpTnA")
            .header("referer", referer)
            .header(header::COOKIE, &cookies_string)
            .header("sec-ch-ua-mobile", "?0")
            .header("sec-ch-ua-platform", "\"Windows\"")
            .header("user-agent", ua)
            .header("x-csrf-token", ct0)
            .header("x-twitter-active-user", "yes")
            .header("x-twitter-auth-type", "OAuth2Session")
            .header("x-twitter-client-language", "en")
            .body(serialized_data)?;
        // println!("request_tw: {:?}", request_tw);
        let mut response_tw = session.send_async(request_tw).await?;

        let text = response_tw.text().await.unwrap_or_default();
        let parsed: Value = serde_json::from_str(&text).unwrap_or_default();

        // println!("parsed0: {:?}", parsed);
        if let Some(redirect_uri) = parsed["redirect_uri"].as_str() {
            let mut response = session.get_async(redirect_uri).await?;
            // let content = response.text().await.unwrap_or_else(|_| "Failed to read response".to_string());
            let text = response.text().await.unwrap_or_default();
            return if text.contains("err=get%2Btwitter%2Buser%2Berror") {
                Ok("Twitter Error connect".to_string())
            } else if text.contains("err=twitter%2Bhas%2Bbeen%2Bused") {
                Ok("Twitter Error connect".to_string())
            } else {
                println!("Twitter text: {}",text);
                Ok("Twitter connect.".to_string())
            };
        }
    } else {
        return Ok("Twitter Error connect: Not auth_code in redirect.".to_string());
    }

    // Ok("Twitter Error connect: Not auth_code in redirect".to_string())
    Ok("Unknown Error.".to_string())
}