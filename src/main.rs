use std::sync::Arc;
use std::time::{Duration,};
use reqwest::{Client, Proxy,};
use log::{error, info};
use rand::prelude::SliceRandom;
use rand::Rng;
use tokio::sync::{Mutex, Semaphore};
use std::io;
use isahc::{
    auth::{Authentication, Credentials},
    prelude::*,
    HttpClient,
    http,
};
mod utils;
mod constants;
use utils::{config,
            chain::bnb_bridge_bnb_opbnb,
            chain::zk_bridge_bnb_opbnb,
            chain::balance_check,
            chain::swaps_bnb_for_wbnb,
            chain::swaps_wbnb_for_bnb,
            error::MyError, };
mod task;
use crate::task::{combonetwork::combonetwork,
                  hunterswap::hunterswap,
                  havenmarket::havenmarket};
use crate::utils::config::Config;


fn generate_user_agent() -> String {
    let platforms = vec![
        "Windows NT 6.1; Win64; x64",
        "Windows NT 6.0; Win64; x64",
        "Windows; U; Windows NT 6.1",
    ];

    let browsers = vec![
        ("Gecko", "Firefox", 48..=90),
        ("AppleWebKit/605.1.15 (KHTML, like Gecko) Version", "Safari", 530..=600),
    ];

    let platform = platforms.choose(&mut rand::thread_rng()).expect("Failed to choose a platform");
    let (engine, browser, versions) = browsers.choose(&mut rand::thread_rng()).expect("Failed to choose a browser");

    let major_version = rand::thread_rng().gen_range(*versions.start()..*versions.end());
    let minor_version = rand::thread_rng().gen_range(0..1000);

    match engine.trim() {
        "Gecko" => format!("Mozilla/5.0 ({}) {}{}/20100101 {}/{}", platform, engine, "", browser, major_version),
        "AppleWebKit/605.1.15 (KHTML, like Gecko) Version" => format!("Mozilla/5.0 ({}) {}{}.{} {}/605.1.15", platform, engine, major_version, minor_version, browser),
        _ => "Unknown User-Agent".to_string()
    }
}

async fn build_client(ip: &str, port: &str, login: &str, pass: &str) -> Result<HttpClient, isahc::Error> {
    let proxy_str = format!("http://{}:{}", ip, port);
    let proxy_uri = proxy_str.parse::<http::Uri>().map_err(|e| {
        let io_error = io::Error::new(io::ErrorKind::InvalidInput, e);
        isahc::Error::from(io_error)
    })?;
    let client = HttpClient::builder()
        .proxy(Some(proxy_uri))
        .proxy_authentication(Authentication::basic())
        .proxy_credentials(Credentials::new(login, pass))
        .cookies()
        .build()?;
    Ok(client)
}

async fn build_web3_client(ip: &str, port: &str, login: &str, pass: &str) -> Result<Client, MyError> {
    let proxy = Proxy::https(format!("http://{}:{}", ip, port))?
        .basic_auth(login, pass);
    let client = Client::builder()
        .proxy(proxy)
        .timeout(Duration::from_secs(30))
        .build()?;
    Ok(client)
}



async fn ip_test (
    session: &HttpClient,
) -> Result<(), isahc::Error> {
    let ip_test = "https://ip.beget.ru/";
    let mut response = session.get_async(ip_test).await?;
    let content = response.text().await.unwrap_or_else(|_| "Failed to read response".to_string());
    let cleaned_content = content.replace(" ", "")
        .replace("{n", "")
        .replace("\n", "");
    println!("IP: {:?}", cleaned_content);
    
    Ok(())
}

async fn start (
    session: &HttpClient,
    web3_client: &Client,
    wallet_data_line: &str,
    ds_token: &str,
    tw_token: &str,
    config: &Config,
    index: usize,
) -> Result<(), MyError>  {


    let ua = generate_user_agent();

    ip_test(&session).await.expect("Proxy not work");
    // ------
    let wallet_parts: Vec<&str> = wallet_data_line.split(":").collect();
    let address = wallet_parts[0].to_string();
    let private_key = wallet_parts[1].to_string();
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

    balance_check(address_without_prefix, web3_client, &config).await;

    // Bridge from BNB to OpBNB via opbnb-bridge
    if config.settings.use_bnb_bridge {
        info!("| {} | Start opbnb-bridge...", address_without_prefix);
        match bnb_bridge_bnb_opbnb(&key_without_prefix, &address_without_prefix, &config, web3_client).await {
            Ok(_c) => info!("| {} | opbnb-bridge - Ok", address_without_prefix),
            Err(e) => {
                error!("| {} | Failed to opbnb-bridge: {}", address_without_prefix, e.to_string());
                // return;
            }
        }
        random_delay(config.settings.delay_action).await;
    }

    // Bridge from BNB to OpBNB via zkbridge
    if config.settings.use_zk_bridge {
        info!("| {} | Start zk-bridge...", address_without_prefix);
        match zk_bridge_bnb_opbnb(&key_without_prefix, &address_without_prefix, &config, web3_client).await {
            Ok(_c) => info!("| {} | zk-bridge - Ok", address_without_prefix),
            Err(e) => {
                error!("| {} | Failed to zk-bridge: {}", address_without_prefix, e.to_string());
                // return;
            }
        }
        random_delay(config.settings.delay_action).await;
    }

    // Swapping of BNB tokens for WBNB
    for _ in 0..random_reps(config.settings.swap_opbnb_for_wbnb_reps) {
        if config.settings.execute_swap_opbnb_for_wbnb {
            info!("| {} | Start swap opBNB -> WBNB...", address_without_prefix);
            match swaps_bnb_for_wbnb(&key_without_prefix, &address_without_prefix, web3_client, &config).await {
                Ok(_c) => info!("| {} | swaps_bnb_for_wbnb - Ok", address_without_prefix),
                Err(e) => {
                    error!("| {} | Failed to swaps_bnb_for_wbnb: {}", address_without_prefix, e.to_string());
                    // return;
                }
            }
            random_delay(config.settings.delay_action).await;
        }
    }

    // Swapping of WBNB tokens for BNB
    for _ in 0..random_reps(config.settings.swap_wbnb_for_opbnb_reps) {
        if config.settings.execute_swap_wbnb_for_opbnb {
            info!("| {} | Start swap WBNB -> opBNB...", address_without_prefix);
            match swaps_wbnb_for_bnb(&key_without_prefix, &address_without_prefix, web3_client, &config).await {
                Ok(_c) => info!("| {} | swaps_wbnb_for_bnb - Ok", address_without_prefix),
                Err(e) => {
                    error!("| {} | Failed to swaps_wbnb_for_bnb: {}", address_without_prefix, e.to_string());
                    // return;
                }
            }
            random_delay(config.settings.delay_action).await;
        }
    }

    if config.settings.mint_combonetwork {
        info!("| {} | Start ComboNetwork...", address_without_prefix);
        let _ = combonetwork(&session.clone(), &web3_client, wallet_data_line, &ds_token, &tw_token, &config, &ua, index).await;
    }

    if config.settings.mint_hunterswap {
        info!("| {} | Start HunterSwap...", address_without_prefix);
        let _ = hunterswap(&session.clone(), &web3_client, wallet_data_line, &ds_token, &tw_token, &config, &ua, index).await;
    }

    if config.settings.mint_havenmarket {
        info!("| {} | Start HavenMarket...", address_without_prefix);
        let _ = havenmarket(&session.clone(), &web3_client, wallet_data_line, &ds_token, &tw_token, &config, &ua, index).await;
    }

    Ok(())
}

fn random_reps(range: (usize, usize)) -> usize {
    let (min, max) = range;
    rand::thread_rng().gen_range(min..=max)
}

async fn random_delay(range: (u64, u64)) {
    let (min, max) = range;
    let delay_duration = rand::thread_rng().gen_range(min..=max);
    tokio::time::sleep(tokio::time::Duration::from_secs(delay_duration)).await;
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up the logger
    utils::logger::setup_logger().unwrap();

    // Read config
    let arc_config = Arc::new(config::read_config("Config/Config.toml").expect("Failed to read config"));

    // Read files
    let proxy_lines = std::fs::read_to_string("FILEs/proxy.txt")?;
    let wallet_data_lines = std::fs::read_to_string("FILEs/address_private_key.txt")?;
    let ds_tokens_lines = std::fs::read_to_string("FILEs/ds_token.txt")?;
    let tw_tokens_lines = std::fs::read_to_string("FILEs/tw_token.txt")?;

    let paired_data: Vec<_> = proxy_lines.lines().map(String::from)
        .zip(wallet_data_lines.lines().map(String::from))
        .zip(ds_tokens_lines.lines().map(String::from))
        .zip(tw_tokens_lines.lines().map(String::from))
        .map(|(((proxy, wallet), ds_token), tw_token)| (proxy, wallet, ds_token, tw_token))
        .collect();

    let max_concurrent_tasks = arc_config.threads.number_of_threads;  // Adjusted
    let semaphore = Arc::new(Semaphore::new(max_concurrent_tasks as usize));

    let futures: Vec<_> = paired_data.into_iter().enumerate().map(|(index, (proxy_line, wallet_data_line, ds_token, tw_token))| {
        let proxy_parts: Vec<String> = proxy_line.split(":").map(|s| s.to_string()).collect();

        let (ip, port, login, pass) = (proxy_parts[0].clone(), proxy_parts[1].clone(), proxy_parts[2].clone(), proxy_parts[3].clone());

        let sema_clone = semaphore.clone();
        let config_clone = arc_config.clone();

        tokio::spawn(async move {
            if index > 0 {
                random_delay(config_clone.threads.delay_between_threads).await;  // Add this at the beginning of the thread
            }

            // Acquire semaphore permit
            let _permit = sema_clone.acquire().await;

            let client = match build_client(&ip, &port, &login, &pass).await {
                Ok(c) => c,
                Err(e) => {
                    error!("| | Failed to build client: {}", e.to_string());
                    return;
                }
            };

            let web3_client = match build_web3_client(&ip, &port, &login, &pass).await {
                Ok(c) => c,
                Err(e) => {
                    error!("| | Failed to build web3 client: {}", e.to_string());
                    return;
                }
            };



            let _ = start(&client, &web3_client, wallet_data_line.as_str(), &ds_token, &tw_token, &config_clone, index).await;


        })
    }).collect();

    futures::future::join_all(futures).await;

    Ok(())
}