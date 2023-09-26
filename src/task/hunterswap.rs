use std::collections::HashMap;
use reqwest::{Client,};
use serde_json::{json, Value};
use log::{error, info};
use isahc::{
    prelude::*,
    HttpClient,
    http,
};
use http::Request;
use rand::Rng;
use crate::{constants::*, utils};
use crate::utils::{config::Config,
                   error::MyError,
                   chain::mint_hunterswap};
use crate::utils::log_status::log_status;


pub async fn hunterswap (
    session: &HttpClient,
    web3_client: &Client,
    wallet_data_line: &str,
    ds_token: &str,
    tw_token: &str,
    config: &Config,
    ua: &str,
    index: usize,
) -> Result<(), MyError>  {
    let wallet_parts: Vec<&str> = wallet_data_line.split(":").collect();
    let address = wallet_parts[0].to_string();
    let private_key = wallet_parts[1].to_string();

    let tw_parts: Vec<&str> = tw_token.split("; ").collect();
    let auth_token = tw_parts[0].split("=").nth(1).unwrap_or("").to_string();
    let ct0 = tw_parts[1].split("=").nth(1).unwrap_or("").to_string();

    // ------
    let parsed = check(&session, &address, &ua).await?;
    // println!("parsed0: {:?}", parsed);
    if let Some(data) = parsed.get("data") {
        if data.get("discord_joined").and_then(Value::as_i64) == Some(0) {
            connect_ds(&session, &address, ds_token, &ua, &config, index).await?;
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        if data.get("telegram_joined").and_then(Value::as_i64) == Some(0) {
            connect_tg(&session, &address, &ua, index).await?;
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

        if data.get("twitter_followed").and_then(Value::as_i64) == Some(0) {
            connect_tw(&session, &address, &auth_token, &ct0, &ua, index).await?;
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        }

    }
    let _parsed = check(&session, &address, &ua).await?;
    // -----
    let address_without_prefix = if address.starts_with("0x") {
        &address[2..]
    } else {
        &address
    };
    let key_without_prefix = if private_key.starts_with("0x") {
        &private_key[2..]
    } else {
        &private_key
    };
    let mint_values = check_mint(&session, &address, &ua).await?;
    // println!("mint_values: {:?}", mint_values);
    if let Some((dummy_id_str, signature)) = mint_values {
        let dummy_id: u64 = dummy_id_str.parse().unwrap_or(0);
        if dummy_id == 0 {
            // return Err(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "Insufficient balance")));
            println!("dummy_id = 0: {:?}", dummy_id);
        }

        // Mint NFT HunterSwap
    if config.settings.mint_hunterswap {
        match mint_hunterswap(&key_without_prefix, &address_without_prefix, &web3_client, dummy_id, signature.as_str(), &config, index).await {
            Ok(_c) => {info!("| {} | mint - Ok", address);
                }
                Err(e) => {
                error!("| {} | Failed to mint: {}", address, e.to_string());
            }
        }
        random_delay(config.settings.delay_action).await;
    }
    }

    Ok(())
}

async fn check (
    session: &HttpClient,
    address: &str,
    ua: &str
) -> Result<Value, isahc::Error> {
    // -------------
    let url0 = format!("https://api.hunterswap.net/api/user?address={}&chain_id=204", address);

    let request0 = Request::builder()
        .method("GET")
        .uri(&url0)
        .header("authority", "api.hunterswap.net")
        .header("accept", "application/json, text/plain, */*")
        .header("content-type", "application/json")
        .header("origin", "https://hunterswap.net")
        .header("referer", "https://hunterswap.net/")
        .header("sec-ch-ua", " ")
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", " ")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-site")
        .header("user-agent", ua)
        .body(())?;
    let mut response0 = session.send_async(request0).await?;

    let text = response0.text().await.unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text).unwrap_or_default();

    // println!("parsed0: {:?}", parsed);

    Ok(parsed)
}

async fn connect_tg (
    session: &HttpClient,
    address: &str,
    ua: &str,
    index: usize,
) -> Result<(), isahc::Error> {
    // -------------
    let url0 = "https://api.hunterswap.net/api/telegram/join".to_string();
    let mut data: HashMap<String, serde_json::Value> = HashMap::new();
    data.insert("address".to_string(), json!(address));
    data.insert("chain_id".to_string(), json!(204));
    let serialized_data = serde_json::to_string(&data).expect("Failed to serialize data");
    // println!("connect_tg_data: {}", &serialized_data);
    let request0 = Request::builder()
        .method("POST")
        .uri(&url0)
        .header("authority", "api.hunterswap.net")
        .header("accept", "application/json, text/plain, */*")
        .header("content-type", "application/json")
        .header("origin", "https://hunterswap.net")
        .header("referer", "https://hunterswap.net/")
        .header("sec-ch-ua", " ")
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", " ")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-site")
        .header("user-agent", ua)
        .body(serialized_data)?;
    let _response0 = session.send_async(request0).await?;

    // let text = response0.text().await.unwrap_or_default();
    // let parsed: Value = serde_json::from_str(&text).unwrap_or_default();
    // println!("connect_tg_parsed0: {:?}", parsed);

    Ok(())
}

async fn check_mint (
    session: &HttpClient,
    address: &str,
    ua: &str
) -> Result<Option<(String, String)>, MyError> {
    // -------------
    let url0 = "https://api.hunterswap.net/api/mint/sign".to_string();
    let mut data: HashMap<String, serde_json::Value> = HashMap::new();
    data.insert("nft_contract".to_string(), json!(NFT_CONTRACT_HS));
    data.insert("mint_contract".to_string(), json!(MINT_CONTRACT_HS));
    data.insert("mint_to".to_string(), json!(address));
    data.insert("chain_id".to_string(), json!(204));
    let serialized_data = serde_json::to_string(&data).expect("Failed to serialize data");
    // println!("data: {}", &serialized_data);
    let request0 = Request::builder()
        .method("POST")
        .uri(&url0)
        .header("authority", "api.hunterswap.net")
        .header("accept", "application/json, text/plain, */*")
        .header("content-type", "application/json")
        .header("origin", "https://hunterswap.net")
        .header("referer", "https://hunterswap.net/")
        .header("sec-ch-ua", " ")
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", " ")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-site")
        .header("user-agent", ua)
        .body(serialized_data).map_err(|err| MyError::ErrorStr(format!("HTTP error: {}", err)))?;
    let mut response0 = session.send_async(request0).await.map_err(MyError::IsahcReqwest)?;

    let text = response0.text().await.unwrap_or_default();
    let parsed: Value = serde_json::from_str(&text).unwrap_or_default();

    // println!("parsed0: {:?}", parsed);

    if let Some((dummy_id, signature)) = {
        let dummy_id = parsed["data"]["dummy_id"]
            .as_str()
            .ok_or(MyError::ErrorStr("Failed to extract dummy_id".to_string()))?;

        let signature = parsed["data"]["signature"]
            .as_str()
            .ok_or(MyError::ErrorStr("Failed to extract signature".to_string()))?;

        Some((dummy_id.to_string(), signature.to_string()))
    } {
        info!("| {} |dummy_id: {}, signature: {}", address, dummy_id, signature);
        Ok(Some((dummy_id, signature)))
    } else {
        error!("Failed to extract dummy_id and signature");
        Ok(None)
    }
}

async fn connect_ds (
    session: &HttpClient,
    address: &str,
    ds_token: &str,
    ua: &str,
    config: &Config,
    index: usize,
) -> Result<(), MyError> {
    // --------------
    let url_ds = format!("https://api.hunterswap.net/api/discord/verify?provider=discord&address={}&chain_id=204", address);

    let request_ds = Request::builder()
        .method("GET")
        .uri(&url_ds)
        .header("authority", "api.hunterswap.net")
        .header("accept", "application/json, text/plain, */*")
        .header("content-type", "application/json")
        .header("origin", "https://hunterswap.net")
        .header("referer", "https://hunterswap.net/")
        .header("sec-ch-ua", " ")
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", " ")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-site")
        .header("user-agent", ua)
        .body(()).map_err(|err| MyError::ErrorStr(format!("HTTP error: {}", err)))?;
    let response_ds = session.send_async(request_ds).await?;

    if let Some(location) = response_ds.headers().get(http::header::LOCATION) {
        let location_str = location.to_str().unwrap_or_default();

        let result = utils::discord::connect_discord(location_str, session, address, ds_token, &ua, &config).await;
        if result?.contains("Error") {
            log_status(index, &address, "hunterswap_ds", "error").await;
        } else {
            log_status(index, &address, "hunterswap_ds", "ok").await;}

    } else {
        error!("| {} | Conncet DS: No location header found in the response.", address);
    }

    Ok(())
}

async fn connect_tw (
    session: &HttpClient,
    address: &str,
    auth_token: &str,
    ct0: &str,
    ua: &str,
    index: usize
) -> Result<(), isahc::Error> {

    let url_ds = format!("https://api.hunterswap.net/api/twitter/verify?address={}&chain_id=204", address);

    let request_tw = Request::builder()
        .method("GET")
        .uri(&url_ds)
        .header("authority", "api.hunterswap.net")
        .header("accept", "application/json, text/plain, */*")
        .header("content-type", "application/json")
        .header("origin", "https://hunterswap.net")
        .header("referer", "https://hunterswap.net/")
        .header("sec-ch-ua", " ")
        .header("sec-ch-ua-mobile", "?0")
        .header("sec-ch-ua-platform", " ")
        .header("sec-fetch-dest", "empty")
        .header("sec-fetch-mode", "cors")
        .header("sec-fetch-site", "same-site")
        .header("user-agent", ua)
        .body(())?;
    let response_tw = session.send_async(request_tw).await?;


    let mut location_str_url = String::new();
    if let Some(location) = response_tw.headers().get(http::header::LOCATION) {
        let _location_str = location.to_str().unwrap_or_default();
        location_str_url = location.to_str().unwrap_or_default().parse().unwrap();
        // println!("location_str_url: {:?}", location_str_url);
        let result = utils::twitter::connect_oauth2(session, &location_str_url, auth_token, ct0, &ua).await;
        if result.clone()?.contains("Error") {
            log_status(index, &address, "hunterswap_tw", "error").await;
        } else {
            log_status(index, &address, "hunterswap_tw", "ok").await;}


        info!("| {} | Connect TW: {:?}", address, result)
    } else {
        error!("| {} | Error connect TW: No location header found in the response.", address);
    }

    Ok(())
}

async fn random_delay(range: (u64, u64)) {
    let (min, max) = range;
    let delay_duration = rand::thread_rng().gen_range(min..=max);
    tokio::time::sleep(tokio::time::Duration::from_secs(delay_duration)).await;
}