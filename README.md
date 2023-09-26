<h1 align="center">Combonetwork mint nft + bridge and swap</h1>
<p align="left">
</p>

<p align="center">
Connects social networks, bridges from BNB to OpBNB and mint NFT.
  +HunterSwap
  +HavenMarket
</p>

## Table of Contents

- [Pre-launch Setup](#pre-launch-setup)
- [Configuration Parameters](#configuration-parameters)
- [Installation](#installation)
- [Usage](#usage)
- [Donation](#donation)


## Pre-launch Setup:
Before launching the program, ensure the following files are correctly filled:

- **FILEs/proxy.txt**: Fill in the proxies in the format `IP:PORT:USER:PASS`. Each proxy should be on a new line.
- **FILEs/address_private_key.txt**: Fill in the `Address:PrivateKey` format. Each wallet should be on a new line.
- **FILEs/ds_token.txt**: Fill in `Njc5Mjxxxxxxxx2.XuMNmg.xxx-Dx86xxxxxx1fO19w_TVxxaq4` with the discord token. Each token must be on a new line.
- FILEs/tw_token.txt: Fill in `auth_token=xxxxxxxxxxxxx; ct0=xxxxxxxxxxxxx` with your twitter data. Each tweet should be on a new line.
- **Capmonster API Key**: To be able to connect to the discord channel, specify your API keys from [Capmonster](https://capmonster.cloud/) in the `Config.toml` file.
- Install Rust and Cargo using the instructions provided [here](https://www.rust-lang.org/learn/get-started).
- Modify the `Config.toml` file for custom settings.

## Configuration Parameters:

### RPC URLs for Different Chains
- **BNB Smart Chain Mainnet**: `https://rpc.ankr.com/bsc`
- **opBNB Mainnet**: `https://opbnb-mainnet-rpc.bnbchain.org`

### Thread Configurations
- **number_of_threads**: Total number of concurrent threads to be executed.
- **delay_between_threads**: Delay (in seconds) between the start of each thread, chosen randomly from the range.

### Global Settings
- **cap_key**: Necessary to enter API key from [Capmonster](https://capmonster.cloud/) service.
- **delay_action**: Delay (in seconds) between actions, chosen randomly from the range.
- **max_retries_connect_server**: Number of attempts to connect to the Discord server.
- **bnb_gwei**: Set the GWEI value for transactions in the BNB Smart Chain Mainnet.
- **bnb_gas**: Set the Gas value for transactions in the BNB Smart Chain Mainnet.
- **opbnb_gwei**: Set the GWEI value for transactions in the opBNB Mainnet.
- **opbnb_gas**: Set the Gas value for transactions in the opBNB Mainnet.
#### Set the corresponding module to `true` to enable or `false` to disable.
- **use_bnb_bridge**: Enable/disable BNB -> opBNB bridge via https://opbnb-bridge.bnbchain.org/deposit.
- **use_zk_bridge**: Enable/disable BNB -> opBNB bridge via https://zkbridge.com/opbnb  (fee ~ 0.0001bnb).
- **value_swap_min**: Minimum BNB amount for the bridge.
- **value_swap_max**: Maximum BNB amount for the bridge.
- **value_swap_decimal**: Decimal precision for BNB amounts.
- **mint_combonetwork**: Enable/disable mint https://combonetwork.io/mint.
- **mint_hunterswap**: Enable/disable mint https://hunterswap.net/mint.
- **mint_havenmarket**: Enable/disable mint https://tests.havenmarket.xyz/mint.
####№ HavenMarket swaps:
- **execute_swap_opbnb_for_wbnb**: Enable/Disable swapping of opBNB for WBNB tokens.
- **swap_opbnb_for_wbnb_reps**: Number of repetitions for opBNB-WBNB token swap.
- **value_swap_min**: Minimum opBNB amount for swap.
- **value_swap_max**: Maximum opBNB amount for swap.
- **value_swap_decimal**: Decimal precision for opBNB amounts.

- **execute_swap_wbnb_for_opbnb**: Enable/Disable swapping of WBNB for BNB tokens.
- **swap_wbnb_for_opbnb_reps**: Number of repetitions for WBNB-BNB token swap.
- **value_swap_min2**: Minimum WBNB amount for swap.
- **value_swap_max2**: Maximum WBNB amount for swap.
- **value_swap_decimal2**: Decimal precision for WBNB amounts.

## Installation:

1. Clone the repository:
```bash
git clone https://github.com/AntonSushkov/ComboNetwork_v2.git
```

2. Navigate to the project directory:
```bash
cd ComboNetwork_v2
```

3. Build the project:
```bash
cargo build
```


## Usage:
To launch the program, navigate to the project directory and run:
```bash
cargo run --release
```

## Donation:
```bash
0x0000002b721da5723238369e69e4c7cf48ca5f0c
```
- _only EVM_



