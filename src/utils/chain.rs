use std::fs;
use log::{error, info};
use rand::Rng;
use reqwest::Client;
use secp256k1::{SecretKey};
use serde_json::{Value};
use tokio::time::{sleep, Duration, Instant};
use web3::{Web3, transports::Http, types::{Address, U256, U64, TransactionParameters}, ethabi};
use web3::contract::{Contract, Options};
use web3::ethabi::Token;
use web3::types::H160;
use crate::{
    constants::*,
    MyError,
    utils::{file_manager::append_to_file,
            config::{Config}},
};
use crate::utils::log_status::log_status;


pub fn generate_web3_clients(client: Client, config: &Config,) -> (Web3<Http>, Web3<Http>) {
    let opbnb_http = Http::with_client(client.clone(), (&config.rpc.opbnb).parse().unwrap());
    let web3_opbnb = Web3::new(opbnb_http);

    let bnb_http = Http::with_client(client.clone(), (&config.rpc.bnb).parse().unwrap());
    let web3_bnb = Web3::new(bnb_http);

    (web3_opbnb, web3_bnb)
}

pub async fn balance_check(address: &str, client: &Client, config: &Config,) {
    let (web3_opbnb, web3_bnb) = generate_web3_clients(client.clone(), &config);
    check_and_log_balance(&web3_opbnb, &address, "OpBNB").await;
    check_and_log_balance(&web3_bnb, &address, "BNB").await;
}

pub async fn bnb_bridge_bnb_opbnb(private_key: &str, address_str: &str, config: &Config, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let (_, web3) = generate_web3_clients(client.clone(), &config);

    let address: Address = address_str.parse().expect("Failed to parse address");

    let random_value = rand::thread_rng().gen_range(config.settings.value_bridge_min..config.settings.value_bridge_max);
    let final_amount = (random_value * 10f64.powi(config.settings.value_ridge_decimal.clone() as i32)).round() / 10f64.powi(config.settings.value_ridge_decimal.clone() as i32);
    let bridge_amount: U256 = U256::from((final_amount * 1e18) as u64);

    let bnb_balance = web3.eth().balance(address, None).await?;
    if bnb_balance < bridge_amount {
        error!("bnb_balance: {:?} < bridge_amount: {}", bnb_balance, bridge_amount);
        return Err(Box::new(MyError::ErrorStr("Insufficient BNB balance".to_string())));
    }

    let bnb_bridge: Address = BNB_BRIDGE.parse().expect("Failed to parse Ethereum address");

    let data = bnb_generate_transfer_data();
    let data_bytes = hex::decode(&data[2..]).expect("Failed to decode hex string to bytes");
    // let gas_price: U256 = web3.eth().gas_price().await.expect("Failed to fetch gas price");

    let nonce = web3.eth().transaction_count(address, None).await?;

    // let gwei_in_wei: U256 = U256::from(1_000_000_000); // 1 * 10^9
    let gwei_in_wei: U256 = U256::from_dec_str(&format!("{:.0}", config.settings.bnb_gwei * 10f64.powi(9))).unwrap();

    let txn_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(bnb_bridge),
        value: U256::from(bridge_amount),
        gas_price: Some(gwei_in_wei),
        gas: U256::from(config.settings.bnb_gas),
        data: data_bytes.into(),
        chain_id: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    // println!("txn_parameters: {:?}", txn_parameters);


    let key_bytes = hex::decode(&private_key).expect("Failed to decode hex");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let signed_txn = web3.accounts().sign_transaction(txn_parameters, &secret_key).await?;

    let _ = sleep(Duration::from_secs(2));

    let tx_hash = web3.eth().send_raw_transaction(signed_txn.raw_transaction).await?;

    match wait_until_tx_finished(&web3, tx_hash, 360).await {
        Ok((success, returned_tx_hash)) => {
            if success {
                info!("| {} | opbnb-bridge Transaction was successful! https://bscscan.com/tx/{:?}", &address_str, returned_tx_hash);
                let _ = sleep(Duration::from_secs(10));
            } else {
                error!("| {} | opbnb-bridge Transaction failed! https://bscscan.com/tx/{:?}", &address_str, returned_tx_hash);
            }
        },
        Err(err) => error!("Error: {}", err),
    }

    let tx_hash_str = format!("{:?}", tx_hash);
    wait_for_bridge_completion(&tx_hash_str, address_str, client.clone()).await;

    Ok(())
}


pub async fn zk_bridge_bnb_opbnb(private_key: &str, address_str: &str, config: &Config, client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let (_, web3) = generate_web3_clients(client.clone(), &config);

    let address: Address = address_str.parse().expect("Failed to parse address");

    let random_value = rand::thread_rng().gen_range(config.settings.value_bridge_min..config.settings.value_bridge_max);
    let final_amount = (random_value * 10f64.powi(config.settings.value_ridge_decimal.clone() as i32)).round() / 10f64.powi(config.settings.value_ridge_decimal.clone() as i32);
    let bridge_amount: U256 = U256::from((final_amount * 1e18) as u64);
    let fee_amount: U256 = U256::from_dec_str(&format!("{:.0}", 0.001 * 10f64.powi(18))).unwrap();
    let value: U256 = bridge_amount + fee_amount;

    let bnb_balance = web3.eth().balance(address, None).await?;
    if bnb_balance < value {
        error!("bnb_balance: {:?} < value: {}", bnb_balance, value);
        return Err(Box::new(MyError::ErrorStr("Insufficient BNB balance".to_string())));
    }

    let zk_bridge: Address = ZK_BRIDGE.parse().expect("Failed to parse Ethereum address");

    let data = generate_transfer_data(bridge_amount, address_str);
    let data_bytes = hex::decode(&data[2..]).expect("Failed to decode hex string to bytes");

    // let gas_price: U256 = web3.eth().gas_price().await.expect("Failed to fetch gas price");

    let nonce = web3.eth().transaction_count(address, None).await?;

    // let gwei_in_wei: U256 = U256::from(1_000_000_000); // 1 * 10^9
    let gwei_in_wei: U256 = U256::from_dec_str(&format!("{:.0}", config.settings.bnb_gwei * 10f64.powi(9))).unwrap();

    let txn_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(zk_bridge),
        value: U256::from(value),
        gas_price: Some(gwei_in_wei),
        gas: U256::from(config.settings.bnb_gas),
        data: data_bytes.into(),
        chain_id: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    // println!("txn_parameters: {:?}", txn_parameters);


    let key_bytes = hex::decode(&private_key).expect("Failed to decode hex");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let signed_txn = web3.accounts().sign_transaction(txn_parameters, &secret_key).await?;

    let _ = sleep(Duration::from_secs(2));

    let tx_hash = web3.eth().send_raw_transaction(signed_txn.raw_transaction).await?;

    match wait_until_tx_finished(&web3, tx_hash, 360).await {
        Ok((success, returned_tx_hash)) => {
            if success {
                info!("| {} | zk-bridge Transaction was successful! https://bscscan.com/tx/{:?}", &address_str, returned_tx_hash);
                let _ = sleep(Duration::from_secs(10));
            } else {
                error!("| {} | zk-bridge Transaction failed! https://bscscan.com/tx/{:?}", &address_str, returned_tx_hash);
            }
        },
        Err(err) => error!("Error: {}", err),
    }

    let tx_hash_str = format!("{:?}", tx_hash);
    wait_for_bridge_completion(&tx_hash_str, address_str, client.clone()).await;

    Ok(())
}

pub async fn mint_hunterswap(private_key: &str, address_str: &str, client: &Client, dummy_id: u64, signature: &str, config: &Config, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (web3, _) = generate_web3_clients(client.clone(), &config);

    let address: Address = address_str.parse().expect("Failed to parse address");


    let opbnb_balance = web3.eth().balance(address, None).await?;
    if opbnb_balance == U256::zero() {
        error!("Insufficient OpBNB balance: {}", opbnb_balance);
        log_status(index, address_str, "mint_hunterswap", "Insufficient OpBNB balance").await;
        return Err(Box::new(MyError::ErrorStr("Insufficient OpBNB balance".to_string())));
    }

    let mint_contract: Address = MINT_CONTRACT_HS.parse().expect("Failed to parse Ethereum address");
    let nft_contract = NFT_CONTRACT_HS;

    let data = hunterswap_mint_data(nft_contract, dummy_id, address_str, signature);
    let data_bytes = hex::decode(&data[2..]).expect("Failed to decode hex string to bytes");
    // println!("data :{:?}", data);
    // let gas_price: U256 = web3.eth().gas_price().await.expect("Failed to fetch gas price");

    let nonce = web3.eth().transaction_count(address, None).await?;

    // let gwei_in_wei: U256 = U256::from(500_000_000); // 0.5 * 10^9
    let gwei_in_wei: U256 = U256::from_dec_str(&format!("{:.0}", &config.settings.opbnb_gwei * 10f64.powi(9))).unwrap();

    let txn_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(mint_contract),
        value: U256::zero(),
        gas_price: Some(gwei_in_wei),
        gas: U256::from(config.settings.opbnb_gas),
        data: data_bytes.into(),
        chain_id: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    // println!("txn_parameters: {:?}", txn_parameters);


    let key_bytes = hex::decode(&private_key).expect("Failed to decode hex");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let signed_txn = web3.accounts().sign_transaction(txn_parameters, &secret_key).await?;

    let _ = sleep(Duration::from_secs(2));

    let tx_hash = web3.eth().send_raw_transaction(signed_txn.raw_transaction).await?;

    match wait_until_tx_finished(&web3, tx_hash, 360).await {
        Ok((success, returned_tx_hash)) => {
            let folder = "result".to_string();
            if success {
                info!("| {} | MINT HunterSwap: Transaction was successful! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
                let data_ok = format!("OK | {} | tx: {}", &address_str, &returned_tx_hash);
                log_status(index, address_str, "mint_hunterswap", "successful").await;
                append_to_file(&data_ok, &folder).await.expect("Error write data in file 'result.txt'");
            } else {
                error!("| {} | MINT HunterSwap: Transaction failed! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
                let data_error = format!("Error | {} | tx: {}", &address_str, &returned_tx_hash);
                log_status(index, address_str, "mint_hunterswap", "failed").await;
                append_to_file(&data_error, &folder).await.expect("Error write data in file 'result.txt'");
            }
        },
        Err(err) => error!("Error: {}", err),
    }

    Ok(())
}

pub async fn mint_combonetwork(private_key: &str, address_str: &str, client: &Client, dummy_id: u64, signature: &str, config: &Config, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (web3, _) = generate_web3_clients(client.clone(), &config);

    let address: Address = address_str.parse().expect("Failed to parse address");

    let opbnb_balance = web3.eth().balance(address, None).await?;
    if opbnb_balance == U256::zero() {
        log_status(index, address_str, "mint_combonetwork", "Insufficient OpBNB balance").await;
        error!("Insufficient OpBNB balance: {}", opbnb_balance);
        return Err(Box::new(MyError::ErrorStr("Insufficient OpBNB balance".to_string())));
    }

    let mint_contract: Address = MINT_CONTRACT_CMB.parse().expect("Failed to parse Ethereum address");
    let nft_contract = NFT_CONTRACT_CMB;

    let data = generate_mint_data(nft_contract, dummy_id, address_str, signature);
    let data_bytes = hex::decode(&data[2..]).expect("Failed to decode hex string to bytes");

    // let gas_price: U256 = web3.eth().gas_price().await.expect("Failed to fetch gas price");

    let nonce = web3.eth().transaction_count(address, None).await?;

    // let gwei_in_wei: U256 = U256::from(500_000_000); // 0.5 * 10^9
    let gwei_in_wei: U256 = U256::from_dec_str(&format!("{:.0}", &config.settings.opbnb_gwei * 10f64.powi(9))).unwrap();

    let txn_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(mint_contract),
        value: U256::zero(),
        gas_price: Some(gwei_in_wei),
        gas: U256::from(config.settings.opbnb_gas),
        data: data_bytes.into(),
        chain_id: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    // println!("txn_parameters: {:?}", txn_parameters);


    let key_bytes = hex::decode(&private_key).expect("Failed to decode hex");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let signed_txn = web3.accounts().sign_transaction(txn_parameters, &secret_key).await?;

    let _ = sleep(Duration::from_secs(2));

    let tx_hash = web3.eth().send_raw_transaction(signed_txn.raw_transaction).await?;

    match wait_until_tx_finished(&web3, tx_hash, 360).await {
        Ok((success, returned_tx_hash)) => {
            let folder = "result".to_string();
            if success {
                info!("| {} | MINT ComboNetwork: Transaction was successful! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
                let data_ok = format!("OK | {} | tx: {}", &address_str, &returned_tx_hash);
                log_status(index, address_str, "mint_combonetwork", "successful").await;
                append_to_file(&data_ok, &folder).await.expect("Error write data in file 'result.txt'");
            } else {
                error!("| {} | MINT ComboNetwork: Transaction failed! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
                let data_error = format!("Error | {} | tx: {}", &address_str, &returned_tx_hash);
                log_status(index, address_str, "mint_combonetwork", "failed").await;
                append_to_file(&data_error, &folder).await.expect("Error write data in file 'result.txt'");
            }
        },
        Err(err) => error!("Error: {}", err),
    }

    Ok(())
}

pub async fn mint_havenmarket(private_key: &str, address_str: &str, client: &Client, dummy_id: u64, signature: &str, config: &Config, index: usize) -> Result<(), Box<dyn std::error::Error>> {
    let (web3, _) = generate_web3_clients(client.clone(), &config);

    let address: Address = address_str.parse().expect("Failed to parse address");


    let opbnb_balance = web3.eth().balance(address, None).await?;
    if opbnb_balance == U256::zero() {
        log_status(index, address_str, "mint_havenmarket", "Insufficient OpBNB balance").await;
        error!("Insufficient OpBNB balance: {}", opbnb_balance);
        return Err(Box::new(MyError::ErrorStr("Insufficient OpBNB balance".to_string())));
    }

    let mint_contract: Address = MINT_CONTRACT_HV.parse().expect("Failed to parse Ethereum address");
    let nft_contract = NFT_CONTRACT_HV;

    let data = havenmarket_mint_data(nft_contract, dummy_id, address_str, signature);
    let data_bytes = hex::decode(&data[2..]).expect("Failed to decode hex string to bytes");
    // println!("data :{:?}", data);
    // let gas_price: U256 = web3.eth().gas_price().await.expect("Failed to fetch gas price");

    let nonce = web3.eth().transaction_count(address, None).await?;

    // let gwei_in_wei: U256 = U256::from(500_000_000); // 0.5 * 10^9
    let gwei_in_wei: U256 = U256::from_dec_str(&format!("{:.0}", &config.settings.opbnb_gwei * 10f64.powi(9))).unwrap();

    let txn_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(mint_contract),
        value: U256::zero(),
        gas_price: Some(gwei_in_wei),
        gas: U256::from(config.settings.opbnb_gas),
        data: data_bytes.into(),
        chain_id: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    // println!("txn_parameters: {:?}", txn_parameters);


    let key_bytes = hex::decode(&private_key).expect("Failed to decode hex");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let signed_txn = web3.accounts().sign_transaction(txn_parameters, &secret_key).await?;

    let _ = sleep(Duration::from_secs(2));

    let tx_hash = web3.eth().send_raw_transaction(signed_txn.raw_transaction).await?;

    match wait_until_tx_finished(&web3, tx_hash, 360).await {
        Ok((success, returned_tx_hash)) => {
            let folder = "result".to_string();
            if success {
                info!("| {} | MINT HavenMarket: Transaction was successful! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
                let data_ok = format!("OK | {} | tx: {}", &address_str, &returned_tx_hash);
                log_status(index, address_str, "mint_havenmarket", "successful").await;
                append_to_file(&data_ok, &folder).await.expect("Error write data in file 'result.txt'");
            } else {
                error!("| {} | MINT HavenMarket: Transaction failed! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
                let data_error = format!("Error | {} | tx: {}", &address_str, &returned_tx_hash);
                log_status(index, address_str, "mint_havenmarket", "failed").await;
                append_to_file(&data_error, &folder).await.expect("Error write data in file 'result.txt'");
            }
        },
        Err(err) => error!("Error: {}", err),
    }

    Ok(())
}

pub async fn swaps_bnb_for_wbnb(private_key: &str, address_str: &str, client: &Client, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let (web3, _) = generate_web3_clients(client.clone(), &config);

    let address_str = if address_str.starts_with("0x") {
        &address_str[2..]
    } else {
        &address_str
    };
    let address: Address = address_str.parse().expect("Failed to parse Ethereum address");

    let hunterswap_router: Address = HUNTERSWAP_ROUTER.parse().expect("Failed to parse Ethereum address");

    let hunterswap_router_abi_bytes: Vec<u8> = fs::read("abi/hunterswap.json")?;
    let hunterswap_router_parsed_abi: ethabi::Contract = ethabi::Contract::load(hunterswap_router_abi_bytes .as_slice())?;

    let random_value = rand::thread_rng().gen_range(config.settings.value_swap_min..config.settings.value_swap_max);
    let parsed_amount = (random_value * 10f64.powi(config.settings.value_swap_decimal.clone() as i32)).round() / 10f64.powi(config.settings.value_swap_decimal.clone() as i32);

    let mut parsed_amount_u256: U256 = U256::from_dec_str(&format!("{:.0}", &parsed_amount * 10f64.powi(18))).unwrap();

    let balance_bnb: U256;
    let mut attempts = 0;
    loop {
        match web3.eth().balance(address, None).await {
            Ok(balance) => {
                balance_bnb = balance;
                break;
            },
            Err(e) => {
                error!("Error fetching balance: {}", e);
                if attempts >= 3 {  // max 3 retries
                    return Err("Failed to fetch balance after multiple attempts.".into());
                }
                attempts += 1;
                sleep(Duration::from_secs(20)).await;
            }
        }
    }

    let gas: u64 = 100_000;
    let current_gas_price: U256 = web3.eth().gas_price().await.expect("Failed to fetch gas price");
    let gas_cost = current_gas_price * U256::from(gas);

    if parsed_amount_u256 > (balance_bnb - gas_cost) {
        let scaled_value = (balance_bnb - gas_cost).low_u64() as f64 * 0.9;
        parsed_amount_u256 = U256::from_dec_str(&(scaled_value.round().to_string())).expect("Failed to convert f64 to U256");
    }

    if parsed_amount_u256 <= U256::zero() {
        return Err("Low balance".into());
    }

    let data0 = hunterswap_router_parsed_abi.function("deposit")
        .expect("deposit function not found in ABI")
        .encode_input(&[])
        .expect("Failed to encode input");

    let gas_price: U256 = U256::from_dec_str(&format!("{:.0}", config.settings.bnb_gwei * 10f64.powi(9))).unwrap();
    // println!("gas_price: {:?}", gas_price);

    let nonce = web3.eth().transaction_count(address, None).await?;


    let txn_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(hunterswap_router),
        value: U256::from(parsed_amount_u256),
        gas_price: Some(gas_price),
        gas: U256::from(100000),
        data: data0.clone().into(),
        chain_id: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    // println!("txn_parameters: {:?}", txn_parameters);

    let key_bytes = hex::decode(&private_key).expect("Failed to decode hex");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let signed_txn = web3.accounts().sign_transaction(txn_parameters, &secret_key).await?;

    let _ = sleep(Duration::from_secs(2));

    let tx_hash = web3.eth().send_raw_transaction(signed_txn.raw_transaction).await?;
    // println!("tx_hash: {:?}", tx_hash);

    match wait_until_tx_finished(&web3, tx_hash, 360).await {
        Ok((success, returned_tx_hash)) => {
            if success {
                info!("| 0x{} | Transaction was successful! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
            } else {
                error!("| 0x{} |Transaction failed! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
            }
        },
        Err(err) => error!("Error: {}", err),
    }

    Ok(())
}


pub async fn swaps_wbnb_for_bnb(private_key: &str, address_str: &str, client: &Client, config: &Config) -> Result<(), Box<dyn std::error::Error>> {
    let (web3, _) = generate_web3_clients(client.clone(), &config);

    let address_str = if address_str.starts_with("0x") {
        &address_str[2..]
    } else {
        &address_str
    };
    let address: Address = address_str.parse().expect("Failed to parse Ethereum address");

    let hunterswap_router: Address = HUNTERSWAP_ROUTER.parse().expect("Failed to parse Ethereum address");
    let wbnb_contract: Address = WBNB_CONTRACT.parse().expect("Failed to parse Ethereum address");

    let hunterswap_router_abi_bytes: Vec<u8> = fs::read("abi/hunterswap.json")?;
    let hunterswap_router_parsed_abi: ethabi::Contract = ethabi::Contract::load(hunterswap_router_abi_bytes .as_slice())?;

    let random_value = rand::thread_rng().gen_range(config.settings.value_swap_min2..config.settings.value_swap_max2);
    let parsed_amount = (random_value * 10f64.powi(config.settings.value_swap_decimal2.clone() as i32)).round() / 10f64.powi(config.settings.value_swap_decimal2.clone() as i32);


    let hunterswap_contract = Contract::new(web3.eth(), hunterswap_router, hunterswap_router_parsed_abi.clone());

    // Step 2: Call the `query` method on the contract instance
    let current_allowance: U256 = hunterswap_contract.query(
        "allowance",
        (address, wbnb_contract),
        None,
        Options::default(),
        None
    )
        .await
        .map_err(|e| web3::Error::Transport(web3::error::TransportError::Message(format!("{:?}", e))))?;

    // info!("Current allowance: {:?}", current_allowance);

    let mut parsed_amount_u256: U256 = U256::from_dec_str(&format!("{:.0}", &parsed_amount * 10f64.powi(18))).unwrap();
    if parsed_amount_u256 > current_allowance {
        send_approval(private_key,
                      address,
                      hunterswap_router,
                      wbnb_contract,  &web3,
                      hunterswap_router_parsed_abi.clone(),
                      parsed_amount_u256,
                      &config).await;
        }

    let balance_wbnb: U256 = hunterswap_contract.query("balanceOf", (address,), None, Default::default(), None).await?;

    if parsed_amount_u256 > balance_wbnb {
        return Err("Low balance".into());
    }
    let data0 = hunterswap_router_parsed_abi.function("withdraw")
        .expect("withdraw function not found in ABI")
        .encode_input(&[Token::Uint(U256::from(parsed_amount_u256))])
        .expect("Failed to encode input");


    // let gas_price: U256 = web3.eth().gas_price().await.expect("Failed to fetch gas price");
    let gas_price: U256 = U256::from_dec_str(&format!("{:.0}", config.settings.bnb_gwei * 10f64.powi(9))).unwrap();
    // println!("gas_price: {:?}", gas_price);

    let nonce = web3.eth().transaction_count(address, None).await?;


    let txn_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(hunterswap_router),
        value: U256::zero(),
        gas_price: Some(gas_price),
        gas: U256::from(100000),
        data: data0.clone().into(),
        chain_id: None,
        transaction_type: None,
        access_list: None,
        max_fee_per_gas: None,
        max_priority_fee_per_gas: None,
    };
    // println!("txn_parameters: {:?}", txn_parameters);

    let key_bytes = hex::decode(&private_key).expect("Failed to decode hex");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let signed_txn = web3.accounts().sign_transaction(txn_parameters, &secret_key).await?;

    let _ = sleep(Duration::from_secs(2));

    let tx_hash = web3.eth().send_raw_transaction(signed_txn.raw_transaction).await?;
    // println!("tx_hash: {:?}", tx_hash);

    match wait_until_tx_finished(&web3, tx_hash, 360).await {
        Ok((success, returned_tx_hash)) => {
            if success {
                info!("| 0x{} | Transaction was successful! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
            } else {
                error!("| 0x{} |Transaction failed! https://opbnbscan.com/tx/{:?}", &address_str, returned_tx_hash);
            }
        },
        Err(err) => error!("Error: {}", err),
    }

    Ok(())
}

async fn send_approval(
    private_key: &str,
    wallet_address: H160,
    contract_address: H160,
    contract_token: H160,
    web3: &Web3<Http>,
    contract: ethabi::Contract,
    amount: U256,
    config: &Config,
) -> web3::Result<()> {

    let data = contract.function("approve")
        .expect("approve function not found in ABI")
        .encode_input(&[Token::Address(contract_token), Token::Uint(amount)])
        .expect("Failed to encode input");

    let nonce = web3.eth().transaction_count(wallet_address, None).await?;

    let gas_price: U256 = U256::from_dec_str(&format!("{:.0}", config.settings.bnb_gwei * 10f64.powi(9))).unwrap();

    let txn_parameters = TransactionParameters {
        nonce: Some(nonce),
        to: Some(contract_address),
        value: U256::zero(),
        gas_price: Some(gas_price),
        gas: U256::from(100000),
        data: data.into(),
        ..Default::default()
    };

    let key_bytes = hex::decode(&private_key).expect("Failed to decode hex");
    let secret_key = SecretKey::from_slice(&key_bytes).expect("Invalid private key bytes");
    let signed_txn = web3.accounts().sign_transaction(txn_parameters, &secret_key).await?;

    sleep(Duration::from_secs(2)).await;

    let tx_hash = web3.eth().send_raw_transaction(signed_txn.raw_transaction).await?;
    info!("Sent approval transaction, tx_hash: {:?}", tx_hash);

    match wait_until_tx_finished(&web3, tx_hash, 360).await {
        Ok((success, _returned_tx_hash)) => {
            if success {
                info!("| {} | Approved - OK", &wallet_address);
            } else {
                error!("| {} | Approved - Error", &wallet_address);
            }
        },
        Err(err) => {
            error!("Error: {}", err);
            return Err(web3::Error::Transport(web3::error::TransportError::Message(format!("Failed to send approval: {:?}", err))));
        },
    }

    Ok(())
}

// async fn random_delay(range: (u64, u64)) {
//     let (min, max) = range;
//     let delay_duration = rand::thread_rng().gen_range(min..=max);
//     tokio::time::sleep(tokio::time::Duration::from_secs(delay_duration)).await;
// }

fn bnb_generate_transfer_data() -> String {
    // Method ID
    let method_id = "b1a1a882";

    // Convert min_gas_limit to hexadecimal and pad to 64 characters (32 bytes)
    let min_gas_limit = format!("{:064x}", 200000);

    // _extra_data
    let _extra_data = "00000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000";

    // Concatenate all components
    format!("0x{}{}{}", method_id, min_gas_limit, _extra_data)
}

fn generate_transfer_data(amount: U256, address: &str) -> String {
    // Method ID
    let method_id = "14d9e096";

    // Convert dst_chain_id to hexadecimal and pad to 64 characters (32 bytes)
    let dst_chain_id_hex = format!("{:064x}", 23);

    // Convert amount to hexadecimal and pad to 64 characters (32 bytes)
    let amount_hex = format!("{:064x}", amount);

    // Convert recipient to hexadecimal and prepend zeros to make it 64 characters (32 bytes)
    let recipient = if address.starts_with("0x") {
        &address[2..]
    } else {
        &address
    };
    let recipient_hex = format!("000000000000000000000000{}", recipient);

    // Concatenate all components
    format!("0x{}{}{}{}", method_id, dst_chain_id_hex, amount_hex, recipient_hex)
}

fn hunterswap_mint_data(
    nft: &str,
    dummy_id: u64,
    mint_to: &str,
    signature: &str
) -> String {
    let method_id = "cea40a51";

    let nft_padded = format_address(nft);
    let dummy_id_hex = format!("{:064x}", dummy_id);
    let info_type_hex = format!("{:064x}", 1);
    let mint_to_padded = format_address(mint_to);
    let signature_data = format_signature(signature);

    format!(
        "0x{}{}{}{}{}00000000000000000000000000000000000000000000000000000000000000a0{}",
        method_id, nft_padded, dummy_id_hex, info_type_hex, mint_to_padded, signature_data
    )
}

fn havenmarket_mint_data(
    nft: &str,
    dummy_id: u64,
    mint_to: &str,
    signature: &str
) -> String {
    let method_id = "cea40a51";

    let nft_padded = format_address(nft);
    let dummy_id_hex = format!("{:064x}", dummy_id);
    let info_type_hex = format!("{:064x}", 0);
    let mint_to_padded = format_address(mint_to);
    let signature_data = format_signature(signature);

    format!(
        "0x{}{}{}{}{}00000000000000000000000000000000000000000000000000000000000000a0{}",
        method_id, nft_padded, dummy_id_hex, info_type_hex, mint_to_padded, signature_data
    )
}

fn format_address(addr: &str) -> String {
    let address = if addr.starts_with("0x") { &addr[2..] } else { addr };
    format!("000000000000000000000000{}", address)
}

fn format_signature(signature: &str) -> String {
    let signat = if signature.starts_with("0x") { &signature[2..] } else { signature };
    let (signature_part1, signature_part2) = signat.split_at(64);
    format!(
        "0000000000000000000000000000000000000000000000000000000000000041{}{}00000000000000000000000000000000000000000000000000000000000000",
        signature_part1, signature_part2
    )
}

fn generate_mint_data(
    nft: &str,
    dummy_id: u64,
    mint_to: &str,
    signature: &str
) -> String {
    let method_id = "b5fd9ec5";

    // Convert nft address to hexadecimal and pad to 64 characters (32 bytes)
    let nft_address = if nft.starts_with("0x") { &nft[2..] } else { nft };
    let nft_padded = format!("000000000000000000000000{}", nft_address);

    // Convert dummy_id to hexadecimal and pad to 64 characters (32 bytes)
    let dummy_id_hex = format!("{:064x}", dummy_id);

    // Convert mint_to address to hexadecimal and pad to 64 characters (32 bytes)
    let mint_address = if mint_to.starts_with("0x") { &mint_to[2..] } else { mint_to };
    let mint_to_padded = format!("000000000000000000000000{}", mint_address);

    // Split the signature into two parts for proper formatting
    let signat = if signature.starts_with("0x") { &signature[2..] } else { signature };
    let (signature_part1, signature_part2) = signat.split_at(64);

    format!(
        "0x{}{}{}{}00000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000041{}{}00000000000000000000000000000000000000000000000000000000000000",
        method_id, nft_padded, dummy_id_hex, mint_to_padded, signature_part1, signature_part2
    )
}

async fn wait_until_tx_finished(web3: &Web3<Http>, tx_hash: web3::types::H256, max_wait_secs: u64) -> Result<(bool, web3::types::H256), &'static str> {
    let start_time = Instant::now();
    let max_wait_time = Duration::from_secs(max_wait_secs);

    while start_time.elapsed() < max_wait_time {
        match web3.eth().transaction_receipt(tx_hash).await {
            Ok(Some(receipt)) => {
                let one = U64::from(1);
                match receipt.status {
                    Some(status) if status == one => {
                        // println!("Transaction was successful! {:?}", tx_hash);
                        return Ok((true, tx_hash));
                    },
                    Some(_) => {
                        error!("Transaction failed! {:?}", receipt);
                        return Ok((false, tx_hash));
                    },
                    None => {
                        tokio::time::sleep(Duration::from_millis(300)).await;
                    },
                }
            },
            Ok(None) => {
                tokio::time::sleep(Duration::from_secs(1)).await;
            },
            Err(_) => {
                if start_time.elapsed() > max_wait_time {
                    error!("FAILED TX: {:?}", tx_hash);
                    return Ok((false, tx_hash));
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }
    Err("Reached maximum wait time without transaction confirmation.")
}

async fn check_and_log_balance(web3: &Web3<Http>, address: &str, network_name: &str) {
    match check_balance(web3, address).await {
        Ok(balance) => {
            info!("| {} | {}", address, format!(
                    "Balance: {} {}",
                    format_balance_to_float(&balance).to_string(),
                    network_name.to_string()));
        },
        Err(e) => {
            eprintln!("Failed to check balance on {}: {}", network_name, e);
        }
    }
}

async fn check_balance(web3: &Web3<Http>, address: &str) -> web3::Result<U256> {
    match address.parse::<Address>() {
        Ok(address_h160) => web3.eth().balance(address_h160, None).await,
        Err(_) => {
            println!("Failed to parse address: {}", address);
            Err(web3::Error::InvalidResponse("Failed to parse address".into()))
        }
    }
}

fn format_balance_to_float(value: &U256) -> f64 {
    value.as_u128() as f64 / 1_000_000_000_000_000_000.0
}

async fn check_status_bridge(tx_hash: &str, address: &str, client: &Client) -> Result<bool, reqwest::Error> {
    let url = format!("https://op-bnb-mainnet-explorer-api.nodereal.io/api/tx/getAssetTransferByAddress?address=0x{}&pageSize=20&page=1&type=deposit", address);
    let response: Value = client.get(&url).send().await?.json().await?;
    // println!("response Value: {:?}", response);

    if let Some(l1_tx_hash) = response["data"]["list"][0]["l1TxHash"].as_str() {
        if l1_tx_hash == tx_hash {
            let receipts_status = response["data"]["list"][0]["receiptsStatus"].as_i64().unwrap_or_default();
            if receipts_status == 1 {
                // println!("Transaction was successful!");
                Ok(true)
            } else {
                // println!("Transaction failed with status {}", receipts_status);
                Ok(false)
            }
        } else {
            // println!("l1TxHash does not match the provided tx_hash");
            Ok(false)
        }
    } else {
        // eprintln!("Failed to extract l1TxHash from the response");
        Ok(false)
    }
}


async fn wait_for_bridge_completion(tx_hash: &str, address: &str, client: Client) {
    let start_time = Instant::now();
    let max_wait_time = Duration::from_secs(900);
    loop {
        if start_time.elapsed() >= max_wait_time {
            error!("Reached maximum wait time without transaction confirmation.");
            break;
        }

        match check_status_bridge(tx_hash, address, &client).await {
            Ok(false) => {
                println!("Bridge is not yet complete...");
                tokio::time::sleep(tokio::time::Duration::from_secs(20)).await;
            },
            Ok(true) => {
                println!("Bridge has completed!");
                break;
            },
            Err(e) => {
                eprintln!("Error while checking: {}", e);
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
}