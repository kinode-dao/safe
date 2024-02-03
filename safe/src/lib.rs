use alloy_sol_types::{sol, SolEvent, SolCall, SolValue, SolEnum};
use anyhow::Result;
use serde::{Deserialize, Serialize, };
use std::collections::HashSet;
use std::collections::hash_map::{ Entry, HashMap, };
use std::str::FromStr;
use kinode_process_lib::{ 
    await_message, get_blob, get_state, http, println, set_state,
    Address, Message, NodeId, LazyLoadBlob, Request, 
};
use kinode_process_lib::eth_alloy::{
    U256,
    Address as AlloyAddress,
    BlockNumberOrTag,
    Bytes,
    CallInput,
    CallRequest,
    Log,
    Filter,
    Provider,
    RpcResponse,
    ValueOrArray,
};

wit_bindgen::generate!({
    path: "wit",
    world: "process",
    exports: {
        world: Component,
    },
});

sol!(SafeL2, "./SafeL2.json");
sol! {
    event ProxyCreation(address proxy, address singleton);
}

#[derive(Clone, Serialize, Deserialize, Debug)]
enum SafeActions {
    AddSafe(AlloyAddress),
    AddPeer(AlloyAddress, NodeId),
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct SafeTx {
    to: AlloyAddress,
    value: u64,
    data: Vec<u8>,
    operation: u8,
    safe_tx_gas: u64,
    base_gas: u64,
    gas_price: u64,
    gas_token: Address,
    refund_receiver: Address,
    nonce: u64,
}

#[derive(Clone, Serialize, Deserialize, Debug, Default)]
struct Safe {
    address: AlloyAddress,
    owners: HashSet<AlloyAddress>,
    txs: HashMap<U256, SafeTx>,
    tx_sigs: HashMap<U256, Vec<Bytes>>,
    threshold: U256,
}

impl Safe {

    fn new(address: AlloyAddress) -> Self {
        Safe {
            address,
            ..Default::default()
        }
    }

}

#[derive(Clone, Serialize, Deserialize, Default)]
struct Peers {
    addr_to_nodes: HashMap<AlloyAddress, HashSet<NodeId>>,
    node_to_addrs: HashMap<NodeId, HashSet<AlloyAddress>>,
    safe_to_nodes: HashMap<AlloyAddress, HashSet<NodeId>>,
    node_to_safes: HashMap<NodeId, HashSet<AlloyAddress>>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct State {
    peers: Peers,
    safe_blocks: HashMap<AlloyAddress, u64>,
    safes: HashMap<AlloyAddress, Safe>,
    ws_channel: u32,
}

struct Component;
impl Guest for Component {
    fn init (our: String) {

        let our = Address::from_str(&our).unwrap();

        let state = match get_state() {
            Some(state) => bincode::deserialize::<State>(&state).unwrap(),
            None => State::default()
        };

        match main(our, state) {
            Ok(_) => {}
            Err(e) => println!("Error: {:?}", e)
        };

    }
}

fn main(our: Address, mut state: State) -> Result<()> {

    let mut provider = Provider::<State> { handlers: HashMap::new(), count: 0 };

    let sub_filter = Filter::new()
        .address(AlloyAddress::from_str("0xc22834581ebc8527d974f8a1c97e1bea4ef910bc")?)
        .from_block(2087031)
        .events(vec!["ProxyCreation(address,address)"]);

    provider.subscribe_logs(
        sub_filter,
Box::new(move |event: Vec<u8>, state: &mut State| {

            let logs: Vec<Log> = match serde_json::from_slice::<ValueOrArray<Log>>(&event) {
                Ok(log) => match log {
                    ValueOrArray::Value(log) => vec![log],
                    ValueOrArray::Array(logs) => logs,
                },
                Err(e) => {
                    println!("Error: {:?}, {:?}", &event, e);
                    return;
                }
            };

            for log in logs {
                let decoded = 
                    ProxyCreation::abi_decode_data(&log.data, false).unwrap();

                state.safe_blocks.insert(
                    decoded.0,
                    log.block_number.expect("REASON").to::<u64>(),
                );
            }

        }),
    );

    http::bind_http_path("/", true, false).unwrap();
    http::bind_http_path("/safe", true, false).unwrap();
    http::bind_http_path("/safe/delegate", true, false).unwrap();
    http::bind_http_path("/safe/peer", true, false).unwrap();
    http::bind_http_path("/safe/send", true, false).unwrap();
    http::bind_http_path("/safe/signer", true, false).unwrap();
    http::bind_http_path("/safes", true, false).unwrap();
    http::bind_ws_path("/", true, false).unwrap();

    println!("Hello from Safe! {:?}", our);

    loop {
        match await_message() {
            Ok(msg) => {

                match msg.is_request() {
                    true => handle_request(&our, &msg, &mut state, &mut provider)?,
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
    provider: &mut Provider<State>
) -> anyhow::Result<()> {

    if !msg.is_request() {
        return Ok(());
    }

    if  msg.source().node != our.node {
            let _ = handle_p2p_request(our, msg, state, provider);
    } else if
        msg.source().node == our.node && 
        msg.source().process == "terminal:distro:sys" {
            let _ = handle_terminal_request(msg);
    } else if 
        msg.source().node == our.node &&
        msg.source().process == "http_server:distro:sys" {
            let _ = handle_http_request(our, msg, state, provider);
    } else if
        msg.source().node == our.node &&
        msg.source().process == "eth_provider:eth_provider:sys" {
            let _ = handle_eth_request(our, msg, state, provider);
    }

    Ok(())

}

fn handle_eth_request(
    our: &Address, 
    msg: &Message, 
    state: &mut State, 
    provider: &mut Provider<State>
) -> anyhow::Result<()> {

    if let Ok(rpc_response) = serde_json::from_slice::<RpcResponse>(&msg.body()) {

        provider.receive(
            msg.metadata().unwrap().parse::<u64>().unwrap(),
            serde_json::to_vec(&rpc_response.result).unwrap(), 
            state
        );
        
    } else {

        println!("safe: got invalid message");

    };

    Ok(())

}

fn handle_p2p_request(
    our: &Address, 
    msg: &Message, 
    state: &mut State,
    provider: &mut Provider<State>
) -> anyhow::Result<()> {

    println!("handling p2p request");

    match serde_json::from_slice::<SafeActions>(msg.body())? {
        SafeActions::AddSafe(safe) => {

            println!("add safe: {:?}", safe);


            match state.safes.entry(safe) {
                Entry::Vacant(entry) => {

                    entry.insert(Safe::new(safe.clone()));

                    subscribe_to_safe(safe.clone(), state, provider)?;

                    state.peers.safe_to_nodes.get_mut(&safe).unwrap().insert(msg.source().node.clone());
                    state.peers.node_to_safes.get_mut(&msg.source().node.clone()).unwrap().insert(safe);

                    Request::new()
                        .target((&our.node, "http_server", "distro", "sys"))
                        .body(websocket_body(state.ws_channel)?)
                        .blob(websocket_blob(serde_json::json!({"safe":safe})))
                        .send()?;

                }
                Entry::Occupied(entry) => {

                }
            }

        }
        SafeActions::AddPeer(safe, peer) => {
            println!("add peer: {:?} {:?}", safe, peer);
        }
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
    provider: &mut Provider<State>
) -> anyhow::Result<()> {

    println!("handling http request");

    match serde_json::from_slice::<http::HttpServerRequest>(msg.body())? {
        http::HttpServerRequest::Http(ref incoming) => {
            match handle_http_methods(our, state, provider, incoming) {
                Ok(()) => Ok(()),
                Err(_) => {
                    http::send_response(
                        http::StatusCode::SERVICE_UNAVAILABLE,
                        None,
                        "Service Unavailable".to_string().as_bytes().to_vec(),
                    )
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
    provider: &mut Provider<State>,
    http_request: &http::IncomingHttpRequest,
) -> anyhow::Result<()> {

    if let Ok(path) = http_request.path() {
        println!("http path: {:?}, method: {:?}", path, http_request.method());
        match &path[..] {
            "/" => handle_http_slash(our, state, http_request),
            "/safe" => handle_http_safe(our, state, provider, http_request),
            "/safes" => handle_http_safes(our, state, http_request),
            "/safe/delegate" => handle_http_safe_delegate(our, state, http_request),
            "/safe/peer" => handle_http_safe_peer(our, state, http_request),
            "/safe/send" => handle_http_safe_send(our, state, http_request),
            "/safe/signer" => handle_http_safe_signer(our, state, http_request),
            &_ => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![])
        }
    } else {
        Ok(())
    }

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
    provider: &mut Provider<State>,
    http_request: &http::IncomingHttpRequest
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
                return http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
            };

            let safe = match serde_json::from_slice::<SafeActions>(&blob.bytes) {
                Ok(SafeActions::AddSafe(safe)) => safe,
                Err(_) => std::process::exit(1),
                _ => return Ok(()),
            };

            match state.safes.entry(safe) {
                Entry::Vacant(v) => {
                    v.insert(Safe::new(safe));
                    subscribe_to_safe(safe, state, provider)?;
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
}

fn handle_http_safe_peer(
    our: &Address, 
    state: &mut State, 
    http_request: &http::IncomingHttpRequest
) -> anyhow::Result<()> { 

    println!("http safe peer {}", http_request.method()?.as_str());

    match http_request.method()?.as_str() {
        "POST" => {

            let (safe, peer) = match serde_json::from_slice::<SafeActions>(&get_blob().unwrap().bytes)? {
                SafeActions::AddPeer(safe, peer) => (safe, peer),
                _ => std::process::exit(1),
            };

            let _ = match state.safes.entry(safe) {
                Entry::Vacant(_) => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]),
                Entry::Occupied(o) => {

                    state.peers.safe_to_nodes.entry(safe.clone()).or_default().insert(peer.clone());
                    state.peers.node_to_safes.entry(peer.clone()).or_default().insert(safe.clone());

                    Request::new()
                        .target(Address{node:peer, process:our.process.clone()})
                        .body(serde_json::to_vec(&SafeActions::AddSafe(safe))?)
                        .send()?;

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
fn handle_http_safe_send(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }
fn handle_http_safe_signer(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }

fn subscribe_to_safe(safe: AlloyAddress, state: &mut State, provider: &mut Provider<State>) -> anyhow::Result<()> {

    let mut owners_call_request = CallRequest::default();
    owners_call_request.to = Some(safe);
    owners_call_request.input = CallInput::new(SafeL2::getOwnersCall::new(()).abi_encode().into());

    provider.call(
        owners_call_request,
        Box::new(move |call: Vec<u8>, state: &mut State| {

            let bytes = &serde_json::from_slice::<Bytes>(call.as_slice()).unwrap();
            let decoded  = match SafeL2::getOwnersCall::abi_decode_returns(bytes, false) {
                Ok(decoded) => decoded,
                Err(_) => return
            };

            let safe = state.safes.get_mut(&safe.clone()).unwrap();

            for owner in decoded._0 {
                safe.owners.insert(owner);
            }

        })
    );

    let mut get_threshold_request = CallRequest::default();
    get_threshold_request.to = Some(safe);
    get_threshold_request.input = CallInput::new(SafeL2::getThresholdCall::new(()).abi_encode().into());

    provider.call(
        get_threshold_request,
        Box::new(move |call: Vec<u8>, state: &mut State| {

            let bytes = &serde_json::from_slice::<Bytes>(call.as_slice()).unwrap();
            let decoded  = match SafeL2::getThresholdCall::abi_decode_returns(bytes, false) {
                Ok(decoded) => decoded,
                Err(_) => return
            };

            let safe = state.safes.get_mut(&safe.clone()).unwrap();
            safe.threshold = decoded._0;

        })
    );

    let added_owner_filter = Filter::new()
        .address(safe.clone())
        .from_block(BlockNumberOrTag::Latest)
        .events(vec![SafeL2::AddedOwner::SIGNATURE]);

    provider.subscribe_logs(
        added_owner_filter,
        Box::new(move |event: Vec<u8>, state: &mut State| {

            let logs: Vec<Log> = match serde_json::from_slice::<ValueOrArray<Log>>(&event) {
                Ok(log) => match log {
                    ValueOrArray::Value(log) => vec![log],
                    ValueOrArray::Array(logs) => logs,
                },
                Err(e) => {
                    println!("Error: {:?}, {:?}", &event, e);
                    return;
                }
            };

            for log in logs {
                let safe = state.safes.get_mut(&log.address).unwrap();
                safe.owners.insert(AlloyAddress::from_word(log.topics[1].into()));
            }

        }),
    );

    let removed_owner_filter = Filter::new()
        .address(safe.clone())
        .from_block(BlockNumberOrTag::Latest)
        .events(vec![SafeL2::RemovedOwner::SIGNATURE]);

    provider.subscribe_logs(
        removed_owner_filter,
        Box::new(move |event: Vec<u8>, state: &mut State| {

            let logs: Vec<Log> = match serde_json::from_slice::<ValueOrArray<Log>>(&event) {
                Ok(log) => match log {
                    ValueOrArray::Value(log) => vec![log],
                    ValueOrArray::Array(logs) => logs,
                },
                Err(e) => {
                    println!("Error: {:?}, {:?}", &event, e);
                    return;
                }
            };

            for log in logs {
                let safe = state.safes.get_mut(&log.address).unwrap();
                safe.owners.remove(&AlloyAddress::from_word(log.topics[1].into()));
            }

        }),
    );

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
        bytes: json.to_string().into()
    }
}