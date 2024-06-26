use alloy_consensus::TxKind;
use alloy_dyn_abi::{DynSolType, DynSolValue, JsonAbiExt};
use alloy_json_abi::{Function, AbiItem, JsonAbi};
use alloy_primitives::{Address as EthAddress, Bytes, FixedBytes, U256, U8};
use alloy_rpc_types::{
    pubsub::{Params, SubscriptionKind, SubscriptionResult},
    request::{TransactionInput, TransactionRequest},
    BlockNumberOrTag, Filter, Log,
};
use alloy_signer::{k256::ecdsa::SigningKey, LocalWallet, Signer, SignerSync, Transaction, Wallet};
use alloy_sol_types::{sol, SolCall, SolEnum, SolEvent, SolValue};

use anyhow::Result;
use kinode_process_lib::{
    await_message,
    get_blob, get_state, http, println, set_state, Address, LazyLoadBlob, Message, NodeId, Request,
    eth::{
        call, 
        estimate_gas, 
        get_block_number, 
        get_chain_id, 
        get_gas_price, 
        get_transaction_count, 
        get_logs, 
        send_raw_transaction, 
        subscribe,
        EthSub, 
    },
};
use serde::{Deserialize, Serialize};
use std::collections::hash_map::{Entry, HashMap};
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};

mod helpers;
use crate::helpers::encryption::{decrypt_data, encrypt_data};

wit_bindgen::generate!({
    path: "wit",
    world: "process",
    exports: {
        world: Component,
    },
});

const SAFE_FACTORY_SUB_ID: u64 = 1;

sol!(SafeL2, "./SafeL2.json");
sol!{ event ProxyCreation(address proxy, address singleton); }

#[derive(Clone, Serialize, Deserialize, Debug)]
enum SafeActions {
    // incoming from frontend
    AddSafeFE(EthAddress),
    AddPeersFE(EthAddress, HashSet<NodeId>),
    AddOwnersFE(EthAddress, HashSet<EthAddress>),
    AddTxFE(EthAddress, EthAddress, u64), // safe, to and amount
    BuildTxFE(EthAddress, EthAddress, u64, Option<Function>, Option<serde_json::Value>), // safe, json abi, json abi args
    AddTxSigFE(EthAddress, U256, NodeId, u64, EthAddress, Bytes), // safe, nonce, orignator, timestamp, signer and signature
    SendTxFE(EthAddress, U256, NodeId, u64), // safe, nonce, orignator, timestamp 
    // outgoing/incoming to/from p2p
    // outgoing to frontend 
    UpdateSafe(Safe),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct SafeTx {
    to: EthAddress,
    value: U256,
    data: Bytes,
    operation: U8,
    safe_tx_gas: U256,
    base_gas: U256,
    gas_price: U256,
    gas_token: EthAddress,
    refund_receiver: EthAddress,
    nonce: U256,
    originator: Option<NodeId>,
    timestamp: u64,
    signatures: HashSet<SafeTxSig>,
    abi: Option<Function>,
    abi_args: Option<serde_json::Value>,
}
impl SafeTx {
    fn to_tuple(&self) -> (
        EthAddress,
        U256,
        Vec<u8>,
        u8,
        U256,
        U256,
        U256,
        EthAddress,
        EthAddress,
        U256,
    ) {
        (
            self.to,
            self.value,
            self.data.0.clone().to_vec(),
            self.operation.to::<u8>(),
            self.safe_tx_gas,
            self.base_gas,
            self.gas_price,
            self.gas_token,
            self.refund_receiver,
            self.nonce,
        )
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, Default, Eq, PartialEq, Hash)]
struct SafeTxSig {
    peer: NodeId,
    addr: EthAddress,
    sig: Bytes,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
struct Safe {
    address: EthAddress,
    owners: HashSet<EthAddress>,
    peers: HashSet<NodeId>,
    txs: BTreeMap<U256, Vec<SafeTx>>,
    threshold: U256,
}

impl Safe {
    fn new(address: EthAddress) -> Self {
        Safe {
            address,
            ..Default::default()
        }
    }
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct Peers {
    addr_to_nodes: HashMap<EthAddress, HashSet<NodeId>>,
    node_to_addrs: HashMap<NodeId, HashSet<EthAddress>>,
    safe_to_nodes: HashMap<EthAddress, HashSet<NodeId>>,
    node_to_safes: HashMap<NodeId, HashSet<EthAddress>>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct State {
    peers: Peers,
    safe_blocks: HashMap<EthAddress, u64>,
    safes: HashMap<EthAddress, Safe>,
    ws_channel: u32,
    block: u64,
    wallet: Option<Vec<u8>>,
}

struct Component;
impl Guest for Component {
    fn init(our: String) {
        let our = Address::from_str(&our).unwrap();

        let mut state = match get_state() {
            Some(state) => bincode::deserialize::<State>(&state).unwrap(),
            None => State::default(),
        };

        let mut wallet = loop {
            match &state.wallet {
                Some(encrypted_wallet) => match decrypt_data(&encrypted_wallet, "password") {
                    Ok(decrypted_wallet) => match String::from_utf8(decrypted_wallet)
                        .ok()
                        .and_then(|wd| wd.parse::<LocalWallet>().ok())
                    {
                        Some(live_wallet) => {
                            println!(
                                "Trader: Loaded wallet with address: {:?}",
                                live_wallet.address()
                            );
                            break Some(live_wallet);
                        }
                        None => println!("Failed to parse wallet, try again."),
                    },
                    Err(_) => println!("Decryption failed, try again."),
                },
                None => {
                    println!("No wallet loaded, input a key: {:?}", our.clone());
                    let wallet_msg = await_message().unwrap();
                    let wallet_data_str = String::from_utf8(wallet_msg.body().to_vec()).unwrap();

                    let encrypted_wallet_data =
                        encrypt_data(wallet_data_str.as_bytes(), "password");

                    state.wallet = Some(encrypted_wallet_data.clone());

                    if let Ok(live_wallet) = wallet_data_str.parse::<LocalWallet>() {
                        println!(
                            "Trader: Loaded wallet with address: {:?}",
                            live_wallet.address()
                        );
                        break Some(live_wallet);
                    } else {
                        println!("Failed to parse wallet key, try again.");
                    }
                }
            }
        }
        .expect("Failed to initialize wallet");

        println!("wallet {:?}", wallet);

        match main(our, state, wallet) {
            Ok(_) => {}
            Err(e) => println!("Error: {:?}", e),
        };
    }
}

fn handle_factory_log(our: &Address, state: &mut State, log: &Log) {
    let decoded = ProxyCreation::abi_decode_data(&log.data, false).unwrap();

    state
        .safe_blocks
        .insert(decoded.0, log.block_number.expect("REASON").to::<u64>());
}

fn handle_safe_added_owner_log(our: &Address, state: &mut State, log: &Log) {
    let safe = state.safes.get_mut(&log.address).unwrap();
    safe.owners
        .insert(EthAddress::from_word(log.topics[1].into()));
}

fn handle_safe_removed_owner_log(our: &Address, state: &mut State, log: &Log) {
    let safe = state.safes.get_mut(&log.address).unwrap();
    safe.owners
        .remove(&EthAddress::from_word(log.topics[1].into()));
}

fn main(our: Address, mut state: State, mut wallet: Wallet<SigningKey>) -> Result<()> {
    let mut sub_handlers: HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>> =
        HashMap::new();

    let safe_factory_filter = Filter::new()
        .address(EthAddress::from_str(
            "0xc22834581ebc8527d974f8a1c97e1bea4ef910bc",
        )?)
        .from_block(2087031)
        .events(vec!["ProxyCreation(address,address)"]);

    // TODO: requires more nuanced implementation due to possible RPC rate limiting
    // if state.block < get_block_number()? {
    //     println!("getting logs");
    //     let logs = get_logs(&safe_factory_filter.clone())?;
    //     println!("got logs {:?}", logs.len());
    //     for log in logs {
    //         handle_factory_log(&our, &mut state, &log);
    //     }
    // }

    let id = sub_handlers.len().try_into().unwrap();
    sub_handlers.insert(id, Box::new(handle_factory_log));
    subscribe(id, safe_factory_filter)?;

    println!("sent sub request");

    http::bind_http_path("/", true, false).unwrap();
    http::bind_http_path("/safe", true, false).unwrap();
    http::bind_http_path("/safe/delegate", true, false).unwrap();
    http::bind_http_path("/safe/peer", true, false).unwrap();
    http::bind_http_path("/safe/tx", true, false).unwrap();
    http::bind_http_path("/safe/tx/build", true, false).unwrap();
    http::bind_http_path("/safe/tx/sign", true, false).unwrap();
    http::bind_http_path("/safe/tx/send", true, false).unwrap();
    http::bind_http_path("/safes", true, false).unwrap();
    http::bind_http_path("/safes/peers", true, false).unwrap();
    http::bind_ws_path("/", true, false).unwrap();

    println!("Hello from Safe! {:?}", our);

    loop {
        match await_message() {
            Ok(msg) => {
                match msg.is_request() {
                    true => handle_request(&our, &msg, &mut state, &mut wallet, &mut sub_handlers)?,
                    false => handle_response(&our, &msg, &mut state)?,
                }
                let _ = set_state(&bincode::serialize(&state).unwrap());
            }
            Err(e) => continue,
            _ => {}
        }
    }
    Ok(())
}

fn handle_response(our: &Address, msg: &Message, state: &mut State) -> anyhow::Result<()> {
    println!("we got a response message {:?}", msg);
    Ok(())
}

fn handle_request(
    our: &Address,
    msg: &Message,
    state: &mut State,
    wallet: &mut Wallet<SigningKey>,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
) -> anyhow::Result<()> {
    println!("handling request");

    if !msg.is_request() {
        return Ok(());
    }

    if msg.source().node != our.node {
        let _ = handle_p2p_request(our, msg, state, sub_handlers);
    } else if msg.source().node == our.node && msg.source().process == "terminal:distro:sys" {
        let _ = handle_terminal_request(msg);
    } else if msg.source().node == our.node && msg.source().process == "http_server:distro:sys" {
        let _ = handle_http_request(our, msg, state, wallet, sub_handlers);
    } else if msg.source().node == our.node && msg.source().process == "eth:distro:sys" {
        let _ = handle_eth_request(our, msg, state, sub_handlers);
    }

    Ok(())
}

fn handle_eth_request(
    our: &Address,
    msg: &Message,
    state: &mut State,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
) -> anyhow::Result<()> {

    println!("~~ eth request ~~");

    let Ok(res) = serde_json::from_slice::<EthSub>(msg.body()) else {
        return Err(anyhow::anyhow!("kns_indexer: got invalid message"));
    };

    if let SubscriptionResult::Log(log) = res.result {
        sub_handlers.get_mut(&res.id).unwrap()(our, state, &log);
    }

    Ok(())
}

fn handle_p2p_request(
    our: &Address,
    msg: &Message,
    state: &mut State,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
) -> anyhow::Result<()> {

    println!("handling p2p request {:?}", msg.body());

    match serde_json::from_slice::<SafeActions>(msg.body()) {
        Ok(SafeActions::UpdateSafe(safe)) => {

            let state_safe = state.safes.entry(safe.address.clone()).or_default();

            state_safe.address = safe.address;
            state_safe.threshold = safe.threshold;
            state_safe.owners.extend(safe.owners.iter().cloned());

            state_safe.peers.extend(safe.peers.iter().cloned());
            state_safe.peers.remove(&our.node);
            state_safe.peers.insert(msg.source().node.clone());

            for (nonce, txs) in safe.txs {
                let state_txs = state_safe.txs.entry(nonce).or_insert_with(Vec::new);
                for tx in txs {
                    if let Some(existing_tx) = state_txs.iter_mut().find(|t| t.originator == tx.originator && t.timestamp == tx.timestamp) {
                        existing_tx.signatures.extend(tx.signatures);
                    } else {
                        state_txs.push(tx);
                    }
                }
            }

            Request::new()
                .target((&our.node, "http_server", "distro", "sys"))
                .body(websocket_body(state.ws_channel)?)
                .blob(websocket_blob(serde_json::json!(&SafeActions::UpdateSafe(state_safe.clone()))))
                .send()?;

        },
        Err(e) => println!("Error: {:?}", e),
        _ => std::process::exit(1),
    }

    Ok(())
}

fn handle_terminal_request(msg: &Message) -> anyhow::Result<()> {
    println!("terminal message: {:?}", msg);
    Ok(())
}

fn handle_http_request(
    our: &Address,
    msg: &Message,
    state: &mut State,
    wallet: &mut Wallet<SigningKey>,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
) -> anyhow::Result<()> {
    println!("handling http request");

    match serde_json::from_slice::<http::HttpServerRequest>(msg.body())? {
        http::HttpServerRequest::Http(ref incoming) => {
            match handle_http_methods(our, state, wallet, sub_handlers, incoming) {
                Ok(()) => Ok(()),
                Err(e) => {
                    http::send_response(
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        None,
                        "Service Unavailable".to_string().as_bytes().to_vec(),
                    );
                    return Ok(());
                }
            }
        }
        http::HttpServerRequest::WebSocketOpen { path, channel_id } => {
            state.ws_channel = channel_id;
            Ok(())
        }
        http::HttpServerRequest::WebSocketClose(channel_id) => Ok(()),
        http::HttpServerRequest::WebSocketPush { .. } => Ok(()),
        _ => Ok(()),
    }
}

fn handle_http_methods(
    our: &Address,
    state: &mut State,
    wallet: &mut Wallet<SigningKey>,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {

    println!("methods");

    if let Ok(path) = http_request.path() {
        println!("http path: {:?}, method: {:?}", path, http_request.method());
        let _ = match &path[..] {
            "/" => handle_http_slash(our, state, http_request),
            "/safe" => handle_http_safe(our, state, sub_handlers, http_request),
            "/safes" => handle_http_safes(our, state, http_request),
            "/safes/peers" => handle_http_safes_peers(our, state, http_request),
            "/safe/delegate" => handle_http_safe_delegate(our, state, http_request),
            "/safe/peer" => handle_http_safe_peer(our, state, http_request),
            "/safe/tx" => handle_http_safe_tx(our, state, http_request),
            "/safe/tx/build" => handle_http_safe_tx_build(our, state, http_request),
            "/safe/tx/sign" => handle_http_safe_tx_sign(our, state, http_request),
            "/safe/tx/send" => handle_http_safe_tx_send(our, state, wallet, http_request),
            &_ => Ok(http::send_response(
                http::StatusCode::BAD_REQUEST,
                None,
                vec![],
            )),
        };
    }

    Ok(())
}

fn handle_http_slash(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {
    match http_request.method()?.as_str() {
        // on GET: give the frontend all of our active games
        "GET" => {
            println!("GET!");
            let _ = http::send_response(http::StatusCode::OK, None, vec![]);
            Ok(())
        }
        "POST" => {
            println!("POST!");
            Ok(())
        }
        "PUT" => {
            println!("PUT!");
            Ok(())
        }
        "DELETE" => {
            println!("DELETE!");
            Ok(())
        }
        _ => {
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
            Ok(())
        }
    }
}

fn handle_http_safe(
    our: &Address,
    state: &mut State,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {
    println!("handling http_safe");

    match http_request.method()?.as_str() {
        "GET" => {
            println!("GET!");
            let _ = http::send_response(http::StatusCode::OK, None, vec![]);
            Ok(())
        }
        "POST" => {

            let Some(blob) = get_blob() else {
                http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
                return Ok(());
            };

            let safe = match serde_json::from_slice::<SafeActions>(&blob.bytes) {
                Ok(SafeActions::AddSafeFE(safe)) => safe,
                Err(_) => std::process::exit(1),
                _ => return Ok(()),
            };

            // TODO: requires more nuanced handling due to possible RPC provider limits
            // if !state.safe_blocks.contains_key(&safe) {
            //     let _ = http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
            //     return Ok(());
            // }

            match state.safes.entry(safe) {
                Entry::Vacant(v) => {
                    v.insert(Safe::new(safe));
                    subscribe_to_safe(our, safe, state, sub_handlers)?;
                    let _ = http::send_response(http::StatusCode::OK, None, vec![]);
                }
                Entry::Occupied(_) => {
                    let _ = http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
                }
            }

            Ok(())
        }
        "PUT" => {
            println!("PUT!");
            Ok(())
        }
        "DELETE" => {
            println!("DELETE!");
            Ok(())
        }
        _ => {
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
            Ok(())
        }
    }
}

fn handle_http_safes(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {
    println!("handling http_safes");

    match http_request.method()?.as_str() {
        "GET" => http::send_response(
            http::StatusCode::OK,
            None,
            serde_json::to_vec(&state.safes)?,
        ),
        _ => http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]),
    }

    Ok(())
}

fn handle_http_safes_peers(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {
    println!("handling http_safes_peers");
    match http_request.method()?.as_str() {
        "GET" => http::send_response(
            http::StatusCode::OK,
            None,
            serde_json::to_vec(&state.peers.safe_to_nodes)?,
        ),
        _ => http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]),
    }

    Ok(())
}

fn handle_http_safe_peer(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {
    println!("http safe peer {}", http_request.method()?.as_str());

    match http_request.method()?.as_str() {
        "POST" => {
            let (safe, peers) =
                match serde_json::from_slice::<SafeActions>(&get_blob().unwrap().bytes)? {
                    SafeActions::AddPeersFE(safe, peers) => (safe, peers),
                    _ => std::process::exit(1),
                };

            println!("safe {:?}, peers {:?}", safe, peers);

            let _ = match state.safes.entry(safe) {
                Entry::Vacant(_) => {
                    http::send_response(http::StatusCode::BAD_REQUEST, None, vec![])
                }
                Entry::Occupied(mut o) => {

                    let state_safe = o.get_mut();

                    state_safe.peers.extend(peers.clone());

                    Request::new()
                        .target((&our.node, "http_server", "distro", "sys"))
                        .body(websocket_body(state.ws_channel)?)
                        .blob(websocket_blob(serde_json::json!(&SafeActions::UpdateSafe(state_safe.clone()))))
                        .send()?;

                    for peer in &state_safe.peers {

                        println!("peer {:?}", peer);

                        Request::new()
                            .target(Address { node: peer.clone(), process: our.process.clone(), })
                            .body(serde_json::to_vec(&SafeActions::UpdateSafe(state_safe.clone()))?)
                            .send()?;

                    }

                    http::send_response(http::StatusCode::OK, None, vec![])
                }
            };
        }
        _ => {
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
        }
    }
    Ok(())
}

fn handle_http_safe_delegate(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {
    Ok(())
}

fn handle_http_safe_tx_build(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {

    println!("http safe tx build");

    match http_request.method()?.as_str() {
        "POST" => {

            println!("post, {:?}", get_blob());

            match serde_json::from_slice::<SafeActions>(&get_blob().unwrap().bytes) {
                Ok(action) => match action {
                    SafeActions::BuildTxFE(safe, to, value,abi, args) => {

                        let _ = match state.safes.entry(safe) {
                            Entry::Vacant(_) => {
                                http::send_response(http::StatusCode::BAD_REQUEST, None, vec![])
                            }
                            Entry::Occupied(mut o) => {
                                println!("occupied");

                                let tx = get_tx(&our, safe, to, value, abi, args);

                                let state_safe = o.get_mut();

                                let nonce_txs = state_safe.txs.entry(tx.nonce).or_insert_with(Vec::new);
                                nonce_txs.push(tx.clone());

                                for peer in &state_safe.peers {

                                    Request::new()
                                        .target(Address { node: peer.clone(), process: our.process.clone(), })
                                        .body(serde_json::to_vec(&SafeActions::UpdateSafe(state_safe.clone()))?)
                                        .send()?;

                                }

                                Request::new()
                                    .target((&our.node, "http_server", "distro", "sys"))
                                    .body(websocket_body(state.ws_channel)?)
                                    .blob(websocket_blob(serde_json::json!(&SafeActions::UpdateSafe(state_safe.clone()))))
                                    .send()?;

                                http::send_response(http::StatusCode::OK, None, vec![])
                            }
                        };

                    },
                    _ => std::process::exit(1),
                },
                Err(e) => {
                    println!("Error ~ ~ : {:?}", e);
                    return Ok(());
                }
            }

        }
        _ => {
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
        }
    }

    Ok(())

}

fn handle_http_safe_tx(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {
    println!("handling http safe tx");

    match http_request.method()?.as_str() {
        "POST" => {
            println!("post");

            let (safe, to, value) =
                match serde_json::from_slice::<SafeActions>(&get_blob().unwrap().bytes)? {
                    SafeActions::AddTxFE(safe, to, value) => (safe, to, value),
                    _ => std::process::exit(1),
                };

            println!("safe: {:?}, to: {:?}, value: {:?}", safe, to, value);

        }
        _ => {
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
        }
    }

    println!("http_safe_send");
    Ok(())
}

fn handle_http_safe_tx_sign(
    our: &Address,
    state: &mut State,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {

    println!("handling http safe tx sign");

    match http_request.method()?.as_str() {
        "GET" => { }
        "POST" => {
            let Some(blob) = get_blob() else {
                http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
                return Ok(());
            };

            println!("blob {:?}", blob);

            let (safe, nonce, originator, timestamp, addr, sig) = match serde_json::from_slice::<SafeActions>(&blob.bytes) {
                Ok(SafeActions::AddTxSigFE(safe, nonce, originator, timestamp, addr, sig)) => 
                    ( safe, nonce, originator, timestamp, addr, sig),
                Err(_) => std::process::exit(1),
                _ => return Ok(()),
            };

            let state_safe = state.safes.get_mut(&safe).unwrap();
            let state_txs = state_safe.txs.get_mut(&nonce).unwrap();
            if let Some((index, tx)) = state_txs.iter_mut().enumerate().find(|(_, tx)| tx.originator == Some(originator.clone()) && tx.timestamp == timestamp) {
                tx.signatures.insert(SafeTxSig { peer: our.node.clone(), addr: addr.clone(), sig: sig.clone() });
            }

            Request::new()
                .target((&our.node, "http_server", "distro", "sys"))
                .body(websocket_body(state.ws_channel)?)
                .blob(websocket_blob(serde_json::json!(&SafeActions::UpdateSafe(state_safe.clone()))))
                .send()?;

            for peer in &state_safe.peers {
                Request::new()
                    .target(Address { node: peer.clone(), process: our.process.clone(), })
                    .body(serde_json::to_vec(&SafeActions::UpdateSafe(state_safe.clone()))?)
                    .send()?;
            }

        }
        _ => {
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
        }
    }

    Ok(())
}

fn handle_http_safe_tx_send(
    our: &Address,
    state: &mut State,
    wallet: &mut Wallet<SigningKey>,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {
    match http_request.method()?.as_str() {
        "POST" => {

            println!("send");

            let Some(blob) = get_blob() else {
                http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
                return Ok(());
            };

            println!("blob {:?}", blob);

            let (safe, nonce, originator, timestamp) = match serde_json::from_slice::<SafeActions>(&blob.bytes) {
                Ok(SafeActions::SendTxFE(safe, nonce, originator, timestamp)) => 
                    ( safe, nonce, originator, timestamp),
                Err(_) => std::process::exit(1),
                _ => return Ok(()),
            };

            let state_safe = state.safes.get_mut(&safe).unwrap();
            let state_txs = state_safe.txs.get_mut(&nonce).unwrap();
            let state_tx = state_txs.iter_mut().find(|tx| tx.originator == Some(originator.clone()) && tx.timestamp == timestamp).unwrap();

            let mut sorted_sigs = state_tx.signatures.iter().cloned().collect::<Vec<SafeTxSig>>();
            sorted_sigs.sort_by(|a,b| a.addr.cmp(&b.addr));

            println!("sorted sigs {:?}", sorted_sigs);

            let sig_bytes = sorted_sigs.iter().flat_map(|sig| sig.sig.clone().into_iter()).collect::<Vec<u8>>();

            let wallet_nonce = get_transaction_count(wallet.address(), None).unwrap();
            let chain_id = get_chain_id().unwrap();
            let gas_price = get_gas_price().unwrap();

            let execute_call = SafeL2::execTransactionCall::new((
                state_tx.to.clone(),
                state_tx.value.clone(),
                state_tx.data.clone().to_vec(),
                state_tx.operation.clone().to::<u8>(),
                state_tx.safe_tx_gas.clone(),
                state_tx.base_gas.clone(),
                state_tx.gas_price.clone(),
                state_tx.gas_token.clone(),
                state_tx.refund_receiver.clone(),
                sig_bytes
            ));
            
            let estimate = match estimate_gas(
                TransactionRequest {
                    from: Some(wallet.address()),
                    to: Some(state_safe.address),
                    value: None,
                    input: TransactionInput::new(execute_call.abi_encode().into()),
                    ..Default::default()
                },
                None,
            ) {
                Ok(estimate) => estimate,
                Err(e) => { 
                    println!("Err ~ ~ ~ {:?}", e); 
                    std::process::exit(1); 
                },
            };

            let mut chain_tx = alloy_consensus::TxLegacy {
                nonce: wallet_nonce.to::<u64>(),
                gas_price: gas_price.to::<u128>(),
                gas_limit: estimate.to::<u64>(),
                to: TxKind::Call(state_safe.address), // Use `TxKind::Call` with the recipient's address
                value: U256::from(0),
                input: execute_call.abi_encode().into(),
                chain_id: Some(chain_id.to::<u64>()),
            };

            let sig = wallet.sign_transaction_sync(&mut chain_tx).unwrap();
            let signed_tx = chain_tx.into_signed(sig);

            let mut buf = vec![];
            signed_tx.encode_signed(&mut buf);

            match send_raw_transaction(buf.into()) {
                Ok(tx_hash) => {
                    println!("sent! with tx_hash {:?}", tx_hash);
                    let _ = http::send_response(http::StatusCode::OK, None, vec![]);
                }
                Err(e) => {
                    println!("Error: {:?}", e);
                    let _ = http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
                }
            }

        }
        _ => {
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
        }
    }

    Ok(())
}

fn get_nonce(safe: EthAddress) -> anyhow::Result<U256> {
    let mut nonce_call_request = TransactionRequest::default();
    nonce_call_request.input =
        TransactionInput::new(SafeL2::nonceCall::new(()).abi_encode().into());
    nonce_call_request.to = Some(safe);

    let nonce_result = call(nonce_call_request, None)?;
    let nonce = SafeL2::nonceCall::abi_decode_returns(&nonce_result, false)?;

    Ok(nonce._0)
}

fn subscribe_to_safe(
    our: &Address,
    safe: EthAddress,
    state: &mut State,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
) -> anyhow::Result<()> {
    let state_safe = state.safes.get_mut(&safe.clone()).unwrap();

    let mut owners_call_request = TransactionRequest::default();
    owners_call_request.input =
        TransactionInput::new(SafeL2::getOwnersCall::new(()).abi_encode().into());
    owners_call_request.to = Some(safe);

    let owners_result = call(owners_call_request, None)?;

    let owners = match SafeL2::getOwnersCall::abi_decode_returns(&owners_result, false){
        Ok(owners) => owners,
        Err(e) => {
            println!("Error: {:?}", e);
            return Ok(())
        }
    } ;

    for owner in owners._0 {
        state_safe.owners.insert(owner);
    }

    let mut get_threshold_request = TransactionRequest::default();
    get_threshold_request.input =
        TransactionInput::new(SafeL2::getThresholdCall::new(()).abi_encode().into());
    get_threshold_request.to = Some(safe);

    let threshold_result = call(get_threshold_request, None)?;
    let threshold = SafeL2::getThresholdCall::abi_decode_returns(&threshold_result, false)?;

    state_safe.threshold = threshold._0;

    Request::new()
        .target((&our.node, "http_server", "distro", "sys"))
        .body(websocket_body(state.ws_channel)?)
        .blob(websocket_blob(serde_json::json!(&SafeActions::UpdateSafe(state_safe.clone()))))
        .send()?;

    let id = sub_handlers.len().try_into().unwrap();
    let added_owner_filter = Filter::new()
        .address(safe.clone())
        .from_block(BlockNumberOrTag::Latest)
        .events(vec![SafeL2::AddedOwner::SIGNATURE]);

    sub_handlers.insert(id, Box::new(handle_safe_added_owner_log));
    subscribe(id, added_owner_filter)?;

    let id = sub_handlers.len().try_into().unwrap();
    let removed_owner_filter = Filter::new()
        .address(safe.clone())
        .from_block(BlockNumberOrTag::Latest)
        .events(vec![SafeL2::RemovedOwner::SIGNATURE]);

    sub_handlers.insert(id, Box::new(handle_safe_removed_owner_log));
    subscribe(id, removed_owner_filter)?;

    Ok(())
}

fn websocket_body(channel_id: u32) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &http::HttpServerRequest::WebSocketPush {
            channel_id,
            message_type: http::WsMessageType::Binary,
        },
    )?)
}

fn websocket_blob(json: serde_json::Value) -> LazyLoadBlob {
    LazyLoadBlob {
        mime: Some("application/json".to_string()),
        bytes: json.to_string().into_bytes(),
    }
}

fn get_tx_data(abi: &Option<Function>, args: &Option<serde_json::Value>) -> Bytes {

    match abi {
        Some(abi) => {

            let inputs = args.clone().unwrap();

            let values = abi.inputs.iter().zip(inputs.as_array().unwrap_or(&vec![])).map(|(input, arg)| {

                match input.ty.as_str() {
                    "uint256" => match arg.as_u64() {
                        Some(val) => DynSolValue::Uint(U256::from(val), 256),
                        None => panic!("Expected u256 value"),
                    },
                    "address" => match arg.as_str() {
                        Some(addr) => EthAddress::from_str(addr).unwrap().into(),
                        None => panic!("Expected address value"),
                    }
                    "bytes" => match arg.as_str() {
                        Some(hex_str) => DynSolValue::Bytes(hex::decode(hex_str.trim_start_matches("0x")).unwrap()),
                        None => panic!("Exptected bytes value"),
                    }
                    "bytes32" | "bytes4" => match arg.as_str() {
                        Some(hex_str) => {
                            let bytes = hex::decode(hex_str).unwrap();
                            DynSolValue::FixedBytes(FixedBytes::from_slice(&bytes), bytes.len())
                        },
                        None => panic!("Expected a fixed bytes value"),
                    },
                    "bytes[]" => match arg.as_array() {
                        Some(arr) => {
                            let bytes_vec = arr.iter().map(|hex_str| {
                                hex::decode(hex_str.as_str().unwrap()).unwrap()
                            }).map(DynSolValue::Bytes).collect();
                            DynSolValue::Array(bytes_vec)
                        },
                        None => DynSolValue::Array(vec![]),
                    },
                    "bool" => match arg.as_bool() {
                        Some(val) => DynSolValue::Bool(val),
                        None => panic!("Expected a bool value"),
                    },
                    _ => unimplemented!("Type {} not implemented", input.ty),
                }
            }).collect::<Vec<DynSolValue>>();

            return abi.abi_encode_input(&values).unwrap().into();

        },
        None => {
            Bytes::default()
        }
    }

}

fn get_tx(
    our: &Address, 
    safe: EthAddress, 
    to: EthAddress, 
    value: u64, 
    abi: Option<Function>, 
    args: Option<serde_json::Value>
) -> SafeTx {

    let tx_data = get_tx_data(&abi, &args);

    let estimate = match estimate_gas(
        TransactionRequest {
            from: Some(safe),
            to: Some(to),
            value: Some(U256::from(value)),
            input: TransactionInput::new(tx_data.clone()),
            ..Default::default()
        },
        None,
    ) {
        Ok(estimate) => estimate,
        Err(e) => { 
            println!("Err ~ ~ ~ {:?}", e); 
            std::process::exit(1); 
        },
    };

    let nonce = get_nonce(safe).unwrap();

    SafeTx {
        to: to,
        value: U256::from(value),
        data: tx_data,
        operation: U8::from(0),
        // gas for the smart contract call
        safe_tx_gas: estimate, 
        // gas for whole transaction
        base_gas: estimate + U256::from(30000),
        gas_price: get_gas_price().unwrap(),
        gas_token: EthAddress::default(),
        refund_receiver: safe,
        nonce: nonce,
        originator: Some(our.node.clone()),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        abi: abi,
        abi_args: args,
        signatures: HashSet::new(),
    }

}