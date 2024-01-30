use alloy_sol_types::{sol, SolEvent};
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
    Address as AlloyAddress,
    AlloyLog,
    AlloySubscribeLogsRequest,
    EthProviderRequests,
    Provider,
    ProviderMethod,
    ValueOrArray,
};
use std::sync::{Arc, Mutex};
use std::cell::RefCell;
use std::borrow::BorrowMut;

wit_bindgen::generate!({
    path: "wit",
    world: "process",
    exports: {
        world: Component,
    },
});

sol! {
    event ProxyCreation(address proxy, address singleton);
}

#[derive(Clone, Serialize, Deserialize, Debug)]
enum SafeActions {
    AddSafe(AddSafe),
    AddPeer(AddPeer)
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct AddPeer {
    safe: AlloyAddress,
    peer: NodeId,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct AddSafe {
    safe: Safe,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
struct SafeUser {
    user: NodeId,
    wallet: AlloyAddress,
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
    delegates: Option<Vec<SafeUser>>,
    peers: Option<HashSet<NodeId>>,
    signers: Option<Vec<SafeUser>>,
    txs: Option<HashMap<u64, SafeTx>>,
    tx_sigs: Option<HashMap<u64, Vec<u8>>>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
struct State {
    ws_channel: u32,
    safe_blocks: HashMap<AlloyAddress, u64>,
    safes: HashMap<AlloyAddress, Safe>,
}

struct Component;
impl Guest for Component {
    fn init (our: String) {

        let our = Address::from_str(&our).unwrap();

        let state = match get_state() {
            Some(state) => bincode::deserialize::<State>(&state).unwrap(),
            None => State {
                ws_channel: 0,
                safe_blocks: HashMap::new(),
                safes: HashMap::new(),
            }
        };

        match main(our, state) {
            Ok(_) => {}
            Err(e) => println!("Error: {:?}", e)
        };

    }
}

fn main(our: Address, mut state: State) -> Result<()> {

    let mut provider = Provider { closures: HashMap::new(), count: 0 };

    let safe_creation_subscription = AlloySubscribeLogsRequest::new()
        .address(AlloyAddress::from_str("0xc22834581ebc8527d974f8a1c97e1bea4ef910bc")?)
        .from_block(2087031)
        .events(vec!["ProxyCreation(address,address)"]);

    provider.subscribe_logs(
        ProviderMethod::SubscribeLogs(safe_creation_subscription),
        Box::new(move |event: Vec<u8>| {
            let log: ValueOrArray<AlloyLog> = serde_json::from_slice(&event).unwrap();
            println!("log from our closure: {:?}", log);
        }),
    );

    // http::bind_http_path("/", true, false).unwrap();
    // http::bind_http_path("/safe", true, false).unwrap();
    // http::bind_http_path("/safe/delegate", true, false).unwrap();
    // http::bind_http_path("/safe/peer", true, false).unwrap();
    // http::bind_http_path("/safe/send", true, false).unwrap();
    // http::bind_http_path("/safe/signer", true, false).unwrap();
    // http::bind_http_path("/safes", true, false).unwrap();
    // http::bind_ws_path("/", true, false).unwrap();

    // println!("Hello from Safe! {:?}", our);

    loop {
        match await_message() {
            Ok(msg) => {

                println!("got a message");

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

fn handle_request(our: &Address, msg: &Message, state: &mut State, provider: &mut Provider) -> anyhow::Result<()> {

    println!("handling request {:?}", msg);

    match serde_json::from_slice::<EthProviderRequests>(msg.body())? {
        EthProviderRequests::RpcResponse(rpc_response) => {
            println!("response.... {:?}", rpc_response);

            let closure_id = msg.metadata().unwrap().parse::<u64>().unwrap();

            provider.receive(closure_id, rpc_response.result.as_bytes().to_vec());

        }
        EthProviderRequests::RpcRequest(rpc_request) => {
            println!("request.... {:?}", rpc_request);

        }
        EthProviderRequests::Test => {
            println!("test");

        }
        _ => {}
    }

    // if !msg.is_request() {
    //     return Ok(());
    // }

    // if  msg.source().node != our.node {
    //         let _ = handle_p2p_request(our, msg, state);
    // } else if
    //     msg.source().node == our.node && 
    //     msg.source().process == "terminal:terminal:nectar" {
    //         let _ = handle_terminal_request(msg);
    // } else if 
    //     msg.source().node == our.node &&
    //     msg.source().process == "http_server:sys:nectar" {

    //         println!("1");
    //         let _ = handle_http_request(our, msg, state);
    // } else if
    //     msg.source().node == our.node &&
    //     msg.source().process == "eth:sys:nectar" {
    //         let _ = handle_eth_request(our, msg, state);
    // }

    Ok(())

}

// fn handle_eth_request(our: &Address, msg: &Message, state: &mut State) -> anyhow::Result<()> {

//     match serde_json::from_slice::<IndexerActions>(msg.body())? {
//         _ => {}
//     }

//     Ok(())

// }

// fn handle_p2p_request(our: &Address, msg: &Message, state: &mut State) -> anyhow::Result<()> {

//     println!("handling p2p request");

//     match serde_json::from_slice::<SafeActions>(msg.body())? {
//         SafeActions::AddSafe(AddSafe{ safe }) => {
//             println!("add safe: {:?}", safe);

//             match state.safes.entry(safe.address) {
//                 Entry::Vacant(entry) => {

//                     entry.insert(safe.clone());

//                     Request::new()
//                         .target((&our.node, "http_server", "sys", "nectar"))
//                         .body(serde_json::to_vec(
//                             &http::HttpServerRequest::WebSocketPush {
//                                 channel_id: state.ws_channel,
//                                 message_type: http::WsMessageType::Binary,
//                             },
//                         )?)
//                         .blob(LazyLoadBlob {
//                             mime: Some("application/json".to_string()),
//                             bytes: serde_json::json!({"safe": safe}).to_string().into_bytes()
//                         })
//                         .send()?;
//                 }
//                 Entry::Occupied(entry) => {

//                 }
//             }

//         }
//         SafeActions::AddPeer(AddPeer{ safe, peer }) => {
//             println!("add peer: {:?} {:?}", safe, peer);
//         }
//     }

//     Ok(())
// }

// fn handle_terminal_request(msg: &Message) -> anyhow::Result<()> {
//     println!("terminal message: {:?}", msg);
//     Ok(())
// }

// fn handle_http_request(our: &Address, msg: &Message, state: &mut State) -> anyhow::Result<()> {

//     println!("handling http request");

//     match serde_json::from_slice::<http::HttpServerRequest>(msg.body())? {
//         http::HttpServerRequest::Http(ref incoming) => {
//             match handle_http_methods(our, state, incoming) {
//                 Ok(()) => Ok(()),
//                 Err(_) => {
//                     http::send_response(
//                         http::StatusCode::SERVICE_UNAVAILABLE,
//                         None,
//                         "Service Unavailable".to_string().as_bytes().to_vec(),
//                     )
//                 }
//             }
//         }
//         http::HttpServerRequest::WebSocketOpen { path, channel_id } => {
//             state.ws_channel = channel_id;
//             Ok(())
//         }
//         http::HttpServerRequest::WebSocketClose (channel_id) => {
//             Ok(())
//         }
//         http::HttpServerRequest::WebSocketPush { .. } => {
//             Ok(())
//         }
//         _ => {
//             Ok(())
//         }
//     }

// }

// fn handle_http_methods(
//     our: &Address, 
//     state: &mut State, 
//     http_request: &http::IncomingHttpRequest,
// ) -> anyhow::Result<()> {

//     if let Ok(path) = http_request.path() {
//         println!("http path: {:?}, method: {:?}", path, http_request.method);
//         match &path[..] {
//             "" => handle_http_slash(our, state, http_request),
//             "safe" => handle_http_safe(our, state, http_request),
//             "safes" => handle_http_safes(our, state, http_request),
//             "safe/delegate" => handle_http_safe_delegate(our, state, http_request),
//             "safe/peer" => handle_http_safe_peer(our, state, http_request),
//             "safe/send" => handle_http_safe_send(our, state, http_request),
//             "safe/signer" => handle_http_safe_signer(our, state, http_request),
//             &_ => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![])
//         }
//     } else {
//         Ok(())
//     }

// }

// fn handle_http_slash(
//     our: &Address,
//     state: &mut State,
//     http_request: &http::IncomingHttpRequest,
// ) -> anyhow::Result<()> {

//     match http_request.method.as_str() {
//         // on GET: give the frontend all of our active games
//         "GET" => {
//             println!("GET!");
//             let _ = http::send_response(http::StatusCode::OK, None, vec![]);
//             Ok(())
//         }
//         "POST" => {
//             println!("POST!");
//             Ok(())
//         }
//         "PUT" => {
//             println!("PUT!");
//             Ok(())
//         }
//         "DELETE" => {
//             println!("DELETE!");
//             Ok(())
//         }
//         _ => {
//             let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
//             Ok(())
//         }
//     }

// }

// fn handle_http_safe(
//     our: &Address, 
//     state: &mut State, 
//     http_request: &http::IncomingHttpRequest
// ) -> anyhow::Result<()> { 

//     println!("handling http_safe");

//     match http_request.method.as_str() {
//         "GET" => {
//             println!("GET!");
//             let _ = http::send_response(http::StatusCode::OK, None, vec![]);
//             Ok(())
//         }
//         "POST" => {
//             let Some(blob) = get_blob() else {
//                 return http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
//             };

//             // let AddSafe { safe } = serde_json::from_slice::<AddSafe>(&blob.bytes)?;
//             let AddSafe { safe } = serde_json::from_slice::<AddSafe>(&blob.bytes).unwrap_or_else(|err| {
//                 println!("Error while parsing JSON: {:?}", err);
//                 std::process::exit(1);
//             });

//             println!("Add Safe: {:?}", safe);

//             match state.safes.entry(safe.address) {
//                 Entry::Vacant(v) => {
//                     v.insert(safe);
//                     let _ = http::send_response(http::StatusCode::OK, None, vec![]);
//                 }
//                 Entry::Occupied(_) => {
//                     let _ = http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]);
//                 }
//             }

//             Ok(())
//         }
//         "PUT" => {
//             println!("PUT!");
//             Ok(())
//         }
//         "DELETE" => {
//             println!("DELETE!");
//             Ok(())
//         }
//         _ => {
//             let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
//             Ok(())
//         }
//     }

// }

// fn handle_http_safes(
//     our: &Address, 
//     state: &mut State, 
//     http_request: &http::IncomingHttpRequest
// ) -> anyhow::Result<()> { 

//     println!("handling http_safes");

//     match http_request.method.as_str() {
//         "GET" => http::send_response(http::StatusCode::OK, None, serde_json::to_vec(&state.safes)?),
//         _ => http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![])
//     }
// }

// fn handle_http_safe_peer(
//     our: &Address, 
//     state: &mut State, 
//     http_request: &http::IncomingHttpRequest
// ) -> anyhow::Result<()> { 
//     println!("safe peer {}", http_request.method.as_str());
//     match http_request.method.as_str() {
//         "POST" => {
//             let blob = get_blob().unwrap();

//             let AddPeer{ peer, safe } = serde_json::from_slice::<AddPeer>(&blob.bytes)?;

//             let _ = match state.safes.entry(safe) {
//                 Entry::Vacant(_) => http::send_response(http::StatusCode::BAD_REQUEST, None, vec![]),
//                 Entry::Occupied(mut o) => {

//                     let saved_safe = o.get_mut();
//                     saved_safe.peers.get_or_insert(HashSet::new()).insert(peer.clone());

//                     Request::new()
//                         .target(Address{node:peer, process:our.process.clone()})
//                         .body(serde_json::to_vec(&SafeActions::AddSafe(AddSafe{ safe: saved_safe.clone() }))?)
//                         .send()?;

//                     http::send_response(http::StatusCode::OK, None, vec![])

//                 }
//             };
//         }
//         _ => {
//             let _ = http::send_response(http::StatusCode::METHOD_NOT_ALLOWED, None, vec![]);
//         }
//     }
//     Ok(()) 
// }

// fn handle_http_safe_delegate(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }
// fn handle_http_safe_send(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }
// fn handle_http_safe_signer(our: &Address, state: &mut State, http_request: &http::IncomingHttpRequest) -> anyhow::Result<()> { Ok(()) }

