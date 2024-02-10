use alloy_consensus::TxKind;
use alloy_json_abi::{JsonAbi, Function};
use alloy_dyn_abi::{DynSolType, DynSolValue};
use alloy_primitives::{Address as EthAddress, Bytes, FixedBytes, U8, U256};
use alloy_rpc_types::{
    pubsub::{Params, SubscriptionKind, SubscriptionResult},
    BlockNumberOrTag, CallInput, CallRequest, Filter, Log,
};
use alloy_signer::{k256::ecdsa::SigningKey, LocalWallet, Signer, SignerSync, Transaction, Wallet};
use alloy_sol_types::{sol, SolEvent, SolCall, SolValue, SolEnum};

use anyhow::Result;
use serde::{Deserialize, Serialize, };
use std::collections::HashSet;
use std::collections::hash_map::{ Entry, HashMap, };
use std::collections::BTreeMap;
use std::str::FromStr;
use std::time::{SystemTime, UNIX_EPOCH};
use kinode_process_lib::{ 
    eth::{
        call, estimate_gas, get_block_number, get_gas_price, get_logs, 
        EthAction, EthResponse
    },
    await_message, get_blob, get_state, http, println, set_state,
    Address, Message, NodeId, LazyLoadBlob, Request, 
};

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
sol! {
    event ProxyCreation(address proxy, address singleton);
}

#[derive(Clone, Serialize, Deserialize, Debug)]
enum SafeActions {
    AddSafe(EthAddress),
    AddPeers(EthAddress, Vec<NodeId>),
    AddOwners(EthAddress, Vec<EthAddress>),
    AddTxFrontend(EthAddress, EthAddress, u64),
    AddTx(EthAddress, SafeTx),
    UpdateThreshold(EthAddress, u64),
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
    originator: Address,
    timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
struct Safe {
    address: EthAddress,
    owners: HashSet<EthAddress>,
    txs: BTreeMap<U256, Vec<SafeTx>>,
    tx_sigs: BTreeMap<U256, Vec<Bytes>>,
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
    fn init (our: String) {

        let our = Address::from_str(&our).unwrap();

        let mut state = match get_state() {
            Some(state) => bincode::deserialize::<State>(&state).unwrap(),
            None => State::default()
        };

        // this block is essentially a messy CLI initialization app,
        // todo fix it up.
        // also todo, save pk in file, store bookmarks etc in state.
        let mut wallet = loop {

            match &state.wallet {
                Some(encrypted_wallet) => {
                    match decrypt_data(&encrypted_wallet, "password") {
                        Ok(decrypted_wallet) => match String::from_utf8(decrypted_wallet)
                            .ok()
                            .and_then(|wd| wd.parse::<LocalWallet>().ok())
                        {
                            Some(live_wallet) => {
                                println!(
                                    "Trader: Loaded wallet with address: {:?}",
                                    live_wallet.address()
                                );
                                break Some(live_wallet)
                            }
                            None => println!("Failed to parse wallet, try again."),
                        },
                        Err(_) => println!("Decryption failed, try again."),
                    }
                }
                None => {
                    println!("No wallet loaded, input a key:");
                    let wallet_msg = await_message().unwrap();
                    let wallet_data_str = String::from_utf8(wallet_msg.body().to_vec()).unwrap();

                    let encrypted_wallet_data = encrypt_data(wallet_data_str.as_bytes(), "password");
                    state.wallet = Some(encrypted_wallet_data.clone());

                    if let Ok(live_wallet) = wallet_data_str.parse::<LocalWallet>() {
                        println!(
                            "Trader: Loaded wallet with address: {:?}",
                            live_wallet.address()
                        );
                        break Some(live_wallet)
                    } else {
                        println!("Failed to parse wallet key, try again.");
                    }
                }
            }
        }
        .expect("Failed to initialize wallet");

        println!("wallet {:?}", wallet);

        match main(our, state) {
            Ok(_) => {}
            Err(e) => println!("Error: {:?}", e)
        };

    }
}

fn handle_factory_log(our: &Address, state: &mut State, log: &Log) {

    let decoded = 
        ProxyCreation::abi_decode_data(&log.data, false).unwrap();

    state.safe_blocks.insert(
        decoded.0,
        log.block_number.expect("REASON").to::<u64>(),
    );

}

fn handle_safe_added_owner_log(our: &Address, state: &mut State, log: &Log) {

    let safe = state.safes.get_mut(&log.address).unwrap();
    safe.owners.insert(EthAddress::from_word(log.topics[1].into()));

}

fn handle_safe_removed_owner_log(our: &Address, state: &mut State, log: &Log) {

    let safe = state.safes.get_mut(&log.address).unwrap();
    safe.owners.remove(&EthAddress::from_word(log.topics[1].into()));

}

fn main(our: Address, mut state: State) -> Result<()> {

    let mut sub_handlers: HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>> = HashMap::new();

    let safe_factory_filter = Filter::new()
        .address(EthAddress::from_str("0xc22834581ebc8527d974f8a1c97e1bea4ef910bc")?)
        .from_block(2087031)
        .events(vec!["ProxyCreation(address,address)"]);

    if state.block < get_block_number()? {
        let logs = get_logs(safe_factory_filter.clone())?;
        for log in logs {
            handle_factory_log(&our, &mut state, &log);
        }
    }

    let params = Params::Logs(Box::new(safe_factory_filter));
    let kind = SubscriptionKind::Logs;

    sub_handlers.insert(sub_handlers.len().try_into().unwrap(), Box::new(handle_factory_log));
    Request::new()
        .target((&our.node, "eth", "distro", "sys"))
        .body(serde_json::to_vec(&EthAction::SubscribeLogs {
            sub_id: SAFE_FACTORY_SUB_ID,
            kind,
            params,
        })?)
        .send()?;

    http::bind_http_path("/", true, false).unwrap();
    http::bind_http_path("/safe", true, false).unwrap();
    http::bind_http_path("/safe/delegate", true, false).unwrap();
    http::bind_http_path("/safe/peer", true, false).unwrap();
    http::bind_http_path("/safe/tx", true, false).unwrap();
    http::bind_http_path("/safe/tx/sign", true, false).unwrap();
    http::bind_http_path("/safes", true, false).unwrap();
    http::bind_http_path("/safes/peers", true, false).unwrap();
    http::bind_ws_path("/", true, false).unwrap();

    println!("Hello from Safe! {:?}", our);

    loop {
        match await_message() {
            Ok(msg) => {
                match msg.is_request() {
                    true => handle_request(&our, &msg, &mut state, &mut sub_handlers)?,
                    false => handle_response(&our, &msg, &mut state)?
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
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>> 
) -> anyhow::Result<()> {

    if !msg.is_request() {
        return Ok(());
    }

    if  msg.source().node != our.node {
            let _ = handle_p2p_request(our, msg, state, sub_handlers);
    } else if
        msg.source().node == our.node && 
        msg.source().process == "terminal:distro:sys" {
            let _ = handle_terminal_request(msg);
    } else if 
        msg.source().node == our.node &&
        msg.source().process == "http_server:distro:sys" {
            let _ = handle_http_request(our, msg, state, sub_handlers);
    } else if
        msg.source().node == our.node &&
        msg.source().process == "eth:distro:sys" {
            let _ = handle_eth_request(our, msg, state, sub_handlers);
    }

    Ok(())

}

fn handle_eth_request(
    our: &Address, 
    msg: &Message, 
    state: &mut State, 
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>> 
) -> anyhow::Result<()> {

    let Ok(res) = serde_json::from_slice::<EthResponse>(msg.body()) else {
        return Err(anyhow::anyhow!("safe: got invalid message"));
    };

    match res {
        EthResponse::Sub { id, result } => match result {
            SubscriptionResult::Log(log) => sub_handlers.get_mut(&id).unwrap()(our, state, &log),
            _ => {}
        },
        _ => {}
    };

    Ok(())

}

fn handle_p2p_request(
    our: &Address, 
    msg: &Message, 
    state: &mut State,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>
) -> anyhow::Result<()> {

    println!("handling p2p request {:?}", msg.body());

    match serde_json::from_slice::<SafeActions>(msg.body()) {
        Ok(SafeActions::AddSafe(safe))=> {

            match state.safes.entry(safe) {
                Entry::Vacant(entry) => {

                    entry.insert(Safe::new(safe.clone()));

                    subscribe_to_safe(&our, safe.clone(), state, sub_handlers)?;

                    let peer = msg.source().node.clone();

                    state.peers.safe_to_nodes.entry(safe.clone()).or_default().insert(peer.clone());
                    state.peers.node_to_safes.entry(peer.clone()).or_default().insert(safe.clone());

                    Request::new()
                        .target((&our.node, "http_server", "distro", "sys"))
                        .body(websocket_body(state.ws_channel)?)
                        .blob(websocket_blob(serde_json::json!(&SafeActions::AddPeers(safe, vec![peer]))))
                        .send()?;

                }
                Entry::Occupied(entry) => {

                }
            }

        }
        Ok(SafeActions::AddTx(safe, tx)) => {

            println!("add tx {:?}", tx);

            match state.safes.entry(safe) {
                Entry::Vacant(_) => {}
                Entry::Occupied(mut o) => {

                    println!("occupied");

                    let txs_by_nonce = o.get_mut().txs.entry(tx.nonce).or_insert_with(Vec::new);

                    if !txs_by_nonce.iter().any(|t| t.originator == tx.originator && t.timestamp == tx.timestamp) {

                        txs_by_nonce.push(tx.clone());

                        Request::new()
                            .target((&our.node, "http_server", "distro", "sys"))
                            .body(websocket_body(state.ws_channel)?)
                            .blob(websocket_blob(serde_json::json!(&SafeActions::AddTx(safe, tx))))
                            .send()?;

                    }


                }
            }

        }
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
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
) -> anyhow::Result<()> {

    println!("handling http request");

    match serde_json::from_slice::<http::HttpServerRequest>(msg.body())? {
        http::HttpServerRequest::Http(ref incoming) => {
            match handle_http_methods(our, state, sub_handlers, incoming) {
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
        http::HttpServerRequest::WebSocketClose (channel_id) => {
            Ok(())
        }
        http::HttpServerRequest::WebSocketPush { .. } => {
            Ok(())
        }
        _ => {
            Ok(())
        }
    }

}

fn handle_http_methods(
    our: &Address, 
    state: &mut State, 
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {

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
            "/safe/tx/sign" => handle_http_safe_tx_sign(our, state, http_request),
            "/safe/tx/send" => handle_http_safe_tx_send(our, state, http_request),
            &_ => Ok(http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]))
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
                Ok(SafeActions::AddSafe(safe)) => safe,
                Err(_) => std::process::exit(1),
                _ => return Ok(()),
            };

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
    http_request: &http::IncomingHttpRequest
) -> anyhow::Result<()> { 

    println!("handling http_safes");

    match http_request.method()?.as_str() {
        "GET" => http::send_response(http::StatusCode::OK, None, serde_json::to_vec(&state.safes)?),
        _ => http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![])
    }

    Ok(())
}

fn handle_http_safes_peers(
    our: &Address, 
    state: &mut State, 
    http_request: &http::IncomingHttpRequest
) -> anyhow::Result<()> { 

    println!("handling http_safes_peers");
    match http_request.method()?.as_str() {
        "GET" => http::send_response
            (http::StatusCode::OK, None, serde_json::to_vec(&state.peers.safe_to_nodes)?),
        _ => http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![])
    }

    Ok(())

}

fn handle_http_safe_peer(
    our: &Address, 
    state: &mut State, 
    http_request: &http::IncomingHttpRequest
) -> anyhow::Result<()> { 

    println!("http safe peer {}", http_request.method()?.as_str());

    match http_request.method()?.as_str() {
        "POST" => {

            let (safe, peers) = match serde_json::from_slice::<SafeActions>(&get_blob().unwrap().bytes)? {
                SafeActions::AddPeers(safe, peers) => (safe, peers),
                _ => std::process::exit(1),
            };

            let _ = match state.safes.entry(safe) {
                Entry::Vacant(_) => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]),
                Entry::Occupied(o) => {

                    Request::new()
                        .target((&our.node, "http_server", "distro", "sys"))
                        .body(websocket_body(state.ws_channel)?)
                        .blob(websocket_blob(serde_json::json!(&SafeActions::AddPeers(safe, peers.clone()))))
                        .send()?;

                    for peer in peers {

                        state.peers.safe_to_nodes.entry(safe.clone()).or_default().insert(peer.clone());
                        state.peers.node_to_safes.entry(peer.clone()).or_default().insert(safe.clone());

                        Request::new()
                            .target(Address{node:peer.clone(), process:our.process.clone()})
                            .body(serde_json::to_vec(&SafeActions::AddSafe(safe))?)
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

fn handle_http_safe_delegate(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }

fn handle_http_safe_tx(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { 

    println!("handling http safe tx");

    match http_request.method()?.as_str() {
        "POST" => {

            println!("post");

            let (safe, to, value) = match serde_json::from_slice::<SafeActions>(&get_blob().unwrap().bytes)? {
                SafeActions::AddTxFrontend(safe, to, value) => (safe, to, value),
                _ => std::process::exit(1),
            };

            println!("safe: {:?}, to: {:?}, value: {:?}", safe, to, value);

            let _ = match state.safes.entry(safe) {
                Entry::Vacant(_) => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]),
                Entry::Occupied(mut o) => {

                    println!("occupied");

                    let estimate = estimate_gas(
                        CallRequest {
                            from: Some(safe),
                            to: Some(to),
                            value: Some(U256::from(value)),
                            input: CallInput::new(Bytes::default()),
                            ..Default::default()
                        },
                        None
                    ).unwrap();

                    println!("estimate: {:?}", estimate);

                    let nonce = get_nonce(safe).unwrap();

                    println!("nonce: {:?}", nonce);

                    let tx = SafeTx {
                        to: to,
                        value: U256::from(value),
                        data: Bytes::default(),
                        operation: U8::from(0),
                        safe_tx_gas: U256::from(30000),
                        base_gas: estimate,
                        gas_price: get_gas_price().unwrap(),
                        gas_token: EthAddress::default(),
                        refund_receiver: safe,
                        nonce: nonce.clone(),
                        originator: our.clone(),
                        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    };

                    let nonce_txs = o.get_mut().txs.entry(nonce).or_insert_with(Vec::new);
                    nonce_txs.push(tx.clone());

                    let peers = state.peers.safe_to_nodes.get(&safe).unwrap();

                    for peer in peers {

                        println!("sending to peer {:?}", peer);

                        let _ = Request::new()
                            .target(Address{node:peer.clone(), process:our.process.clone()})
                            .body(serde_json::to_vec(&SafeActions::AddTx(safe, tx.clone()))?)
                            .send()?;

                    }

                    Request::new()
                        .target((&our.node, "http_server", "distro", "sys"))
                        .body(websocket_body(state.ws_channel)?)
                        .blob(websocket_blob(serde_json::json!(&SafeActions::AddTx(safe, tx))))
                        .send()?;

                    http::send_response(http::StatusCode::OK, None, vec![])

                }
            };
        }
        _ => {
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]); 
        }

    }

    println!("http_safe_send");
    Ok(())

}

fn handle_http_safe_tx_sign(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { 

    match http_request.method()?.as_str() {
        "POST" => {

        }
        _ => { 
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]); 
        }

    }

    Ok(()) 
}

fn handle_http_safe_tx_send(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { 

    match http_request.method()?.as_str() {
        "POST" => {

        }
        _ => { 
            let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]); 
        }

    }

    Ok(()) 

}

fn get_nonce(safe: EthAddress) -> anyhow::Result<U256> {

    let mut nonce_call_request = CallRequest::default();
    nonce_call_request.input = CallInput::new(SafeL2::nonceCall::new(()).abi_encode().into());
    nonce_call_request.to = Some(safe);

    let nonce_result = call(nonce_call_request, None)?;
    let nonce = SafeL2::nonceCall::abi_decode_returns(&nonce_result, false)?;

    Ok(nonce._0)

}

fn subscribe_to_safe(
    our: &Address, 
    safe: EthAddress, 
    state: &mut State,
    sub_handlers: &mut HashMap<u64, Box<dyn FnMut(&Address, &mut State, &Log) + Send>>
) -> anyhow::Result<()> {

    let state_safe = state.safes.get_mut(&safe.clone()).unwrap();

    let mut owners_call_request = CallRequest::default();
    owners_call_request.input = CallInput::new(SafeL2::getOwnersCall::new(()).abi_encode().into());
    owners_call_request.to = Some(safe);

    let owners_result = call(owners_call_request, None)?;
    let owners = SafeL2::getOwnersCall::abi_decode_returns(&owners_result, false)?;

    for owner in owners._0 { state_safe.owners.insert(owner); }

    let mut get_threshold_request = CallRequest::default();
    get_threshold_request.input = CallInput::new(SafeL2::getThresholdCall::new(()).abi_encode().into());
    get_threshold_request.to = Some(safe);

    let threshold_result = call(get_threshold_request, None)?;
    let threshold = SafeL2::getThresholdCall::abi_decode_returns(&threshold_result, false)?;

    state_safe.threshold = threshold._0;

    Request::new()
        .target((&our.node, "http_server", "distro", "sys"))
        .body(websocket_body(state.ws_channel)?)
        .blob(websocket_blob(serde_json::json!(&SafeActions::AddOwners(safe, state_safe.owners.clone().into_iter().collect()))))
        .send()?;

    Request::new()
        .target((&our.node, "http_server", "distro", "sys"))
        .body(websocket_body(state.ws_channel)?)
        .blob(websocket_blob(serde_json::json!(&SafeActions::UpdateThreshold(safe, state_safe.threshold.clone().to::<u64>()))))
        .send()?;

    let added_owner_filter = Filter::new()
        .address(safe.clone())
        .from_block(BlockNumberOrTag::Latest)
        .events(vec![SafeL2::AddedOwner::SIGNATURE]);

    sub_handlers.insert(sub_handlers.len().try_into().unwrap(), Box::new(handle_safe_added_owner_log));
    Request::new()
        .target((&our.node, "eth", "distro", "sys"))
        .body(serde_json::to_vec(&EthAction::SubscribeLogs {
            sub_id: sub_handlers.len().try_into().unwrap(),
            kind: SubscriptionKind::Logs,
            params: Params::Logs(Box::new(added_owner_filter)),
        })?)
        .send()?;

    let removed_owner_filter = Filter::new()
        .address(safe.clone())
        .from_block(BlockNumberOrTag::Latest)
        .events(vec![SafeL2::RemovedOwner::SIGNATURE]);

    sub_handlers.insert(sub_handlers.len().try_into().unwrap(), Box::new(handle_safe_removed_owner_log));
    Request::new()
        .target((&our.node, "eth", "distro", "sys"))
        .body(serde_json::to_vec(&EthAction::SubscribeLogs {
            sub_id: sub_handlers.len().try_into().unwrap(),
            kind: SubscriptionKind::Logs,
            params: Params::Logs(Box::new(removed_owner_filter)),
        })?)
        .send()?;

    Ok(())

}

fn websocket_body(channel_id: u32) -> anyhow::Result<Vec<u8>> {
    Ok(serde_json::to_vec(
        &http::HttpServerRequest::WebSocketPush {
            channel_id,
            message_type: http::WsMessageType::Binary,
        }
    )?)
}

fn websocket_blob(json: serde_json::Value) -> LazyLoadBlob {
    LazyLoadBlob {
        mime: Some("application/json".to_string()),
        bytes: json.to_string().into_bytes()
    }
}
