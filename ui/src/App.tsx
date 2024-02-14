import { useState, useEffect, useCallback } from "react";
import { useWeb3React } from "@web3-react/core";
import { hooks, metaMask } from "./connectors/metamask";
import { ethers } from "ethers";
import reactLogo from "./assets/react.svg";
import viteLogo from "./assets/vite.svg";
import NectarEncryptorApi from "@uqbar/client-encryptor-api";
import ConnectWallet from "./components/ConnectWallet";
import Header from "./components/Header";
import _ from "lodash";
import "./App.css";

const { useIsActivating, useChainId } = hooks;

const BASE_URL = import.meta.env.BASE_URL;
if (window.our) window.our.process = BASE_URL?.replace("/", "");

const PROXY_TARGET = `${(import.meta.env.VITE_NODE_URL || "http://localhost:8080")}${BASE_URL}`;

console.log("PROXY_TARGET", PROXY_TARGET);

// This env also has BASE_URL which should match the process + package name
const WEBSOCKET_URL = import.meta.env.DEV
  ? `${PROXY_TARGET.replace('http', 'ws')}`
  : undefined;

function App() {

  const { account, isActive } = useWeb3React()
  const isActivating = useIsActivating();
  const chainId = useChainId();

  console.log("account", account, "isActive", isActive);
  console.log("isActivating", isActivating, "chainId", chainId);

  const [nodeConnected, setNodeConnected] = useState(true);
  const [api, setApi] = useState<NectarEncryptorApi | undefined>();

  const [ connectOpen, setConnectOpen ] = useState<boolean>(false);
  const openConnect = () => setConnectOpen(true)
  const closeConnect = () => setConnectOpen(false)

  type Safe = {
    address: string,
    peers: string[],
    owners: string[],
    delegates: string[],
    txs: { [key: string]: SafeTx[] },
    tx_sigs: string[],
    threshold: number
  };

  type SafeTx = {
      to: string,
      value: number,
      data: string,
      operation: number,
      safe_tx_gas: number,
      base_gas: number,
      gas_price: number,
      gas_token: string,
      refund_receiver: string,
      nonce: number,
      originator: string,
      timestamp: number,
      signatures: SafeTxSig[],
  }

  type SafeTxSig = { 
    peer: string,
    signature: string,
  }

  const [safes, setSafes] = useState<Safe[]>([]);
  const [newSafe, setNewSafe] = useState("");
  const [newPeer, setNewPeer] = useState("");
  const [newSigner, setNewSigner] = useState("");
  const [newDelegate, setNewDelegate] = useState("");

  const addSafe = async (safe) => {

    const checksum = ethers.getAddress(safe);

    console.log("CHECKSUM", checksum);

    let response = await fetch(`${BASE_URL}/safe`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ AddSafe: checksum })
    })

    console.log("~~~SAFE!!!!", response);

    if (response.status == 200) {
      setSafes(safes.concat({ address: checksum } as Safe))
    }

  }

  const sendDev = async (safe, to) => {

    console.log("sending to dev")
    let response = await fetch(`${BASE_URL}/safe/tx`, { 
      method: "POST", 
      body: JSON.stringify({ AddTxFrontend: [safe, to, 1] })
    })

    console.log("resposne", response);
    let json = await response.json();
    console.log("json", json);

  }

  const addPeer = async (safe, peer) => {
    await fetch(`${BASE_URL}/safe/peer`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({AddPeers:[safe, [peer]]})
    })
  }

  const signTx = async (safe, nonce, originator, timestamp) => {

    await fetch(`${BASE_URL}/safe/tx/sign`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({AddTxSig:[safe, nonce, originator, timestamp]})
    })
  }

  // bootstrap
  useEffect(() => { (async() => {

    let safes = []
    let safes_response = await (await fetch(`${BASE_URL}/safes`, { method: "GET" })).json();
    let peers_response = await (await fetch(`${BASE_URL}/safes/peers`, { method: "GET" })).json();

    for (let key in safes_response) {
      let safe = { address: key, ...safes_response[key] }
      if (peers_response[key]) safe.peers = peers_response[key]
      safes.push(safe)
    }

    setSafes(safes)

  })()}, []);

  useEffect(() => {
    // Connect to the nectar node via websocket
    if (window.our?.node && window.our?.process) {
      const api = new NectarEncryptorApi({
        uri: WEBSOCKET_URL,
        nodeId: window.our.node,
        processId: window.our.process,
        onOpen: (_event, _api) => { },
        onMessage: (json: string | Blob) => {
          console.log("GETTING MESAGE", json)

          if (typeof json === 'string') { } 
          else {
            const reader = new FileReader();
            reader.onload = function(event) {
              if (typeof event?.target?.result === 'string') {
                try {
                  const pkt = JSON.parse(event.target.result);

                  console.log("PKT!!!!", pkt)

                  Object.keys(pkt).forEach(key => {
                    switch (key) {
                      case "AddOwners": {
                        const safe = ethers.getAddress(pkt[key][0]);
                        setSafes(prevSafes => prevSafes.map(s => {
                          if (s.address != safe) return s
                          else {
                            const newOwners = s.owners ? [...s.owners] : [];
                            pkt[key][1].forEach(owner => {
                              if (!newOwners.find(o => o == owner)) newOwners.push(owner)
                            })
                            return { ...s, owners: newOwners }
                          }
                        }))
                        break;
                      }
                      case "AddPeers": {
                        const safe = ethers.getAddress(pkt[key][0]);
                        setSafes(prevSafes => prevSafes.map(s => {
                            if (s.address != safe) return s 
                            else {
                              const newPeers = s.peers ? [...s.peers] : [];
                              pkt[key][1].forEach(peer => {
                                if (!newPeers.find(p => p == peer)) newPeers.push(peer)
                              })
                              return { ...s, peers: newPeers }
                            }
                        }))
                        break;
                      }
                      case "AddSafe": {
                        const safe = ethers.getAddress(pkt[key]);
                        setSafes(prevSafes => {
                          if (!prevSafes.some(s => s.address == safe))
                            return [...prevSafes, {address: safe} as Safe]
                          else 
                            return prevSafes
                        })
                        break;
                      }
                      case "AddTx": {
                        setSafes(prevSafes => prevSafes.map(s => 
                          s.address == pkt[key][0] 
                            ? { ...s, 
                                txs: {
                                  ...s.txs,
                                  [pkt[key][1].nonce]: s.txs && s.txs[pkt[key][1].nonce]
                                    ? [...s.txs[pkt[key][1].nonce], pkt[key][1]]
                                    : [pkt[key][1]]
                                }
                              }
                            : s
                        ));
                        break;
                      }
                      case "UpdateThreshold": {
                        const safe = ethers.getAddress(pkt[key][0]);
                        setSafes(prevSafes => prevSafes
                            .map(s => s.address == safe ? { ...s, threshold: pkt[key][1] } : s)
                        )
                      }
                    }
                  })
                } catch (error) {
                  console.error("Error parsing WebSocket message", error);
                }
              }
            };
            reader.readAsText(json);
          }
        },
      });

      setApi(api);
    } else {
      setNodeConnected(false);
    }
  }, []);

  const TxComponent = ({txs}: {txs: SafeTx[]}) => {
    return (
      <div>
        <div> Nonce: {txs[0].nonce} </div>
        { txs.map(tx => 
          <div>
            <p> To: {tx.to} </p>
            <p> Value: {tx.value } </p>
            <button onClick={e=> signTx(tx.nonce, tx.originator, tx.timestamp)}> Sign </button>
            { txs[0].signatures.map(sig => <p> { "✅ " + sig.peer} </p>) } 
          </div>
        ) }
      </div>
    )
  }

  console.log("SAFES!!!!!!", safes)

  return (
    <div style={{ width: "100%" }}>
      <div style={{ position: "absolute", top: 4, left: 8 }}>
        ID: <strong>{window.our?.node}</strong>
      </div>
      <Header {...{openConnect, closeConnect, msg: "Header" }} />
      <ConnectWallet {...{connectOpen, closeConnect}} />
      {!nodeConnected && (
        <div className="node-not-connected">
          <h2 style={{ color: "red" }}>Node not connected</h2>
          <h4>
            You need to start a node at {PROXY_TARGET} before you can use this UI
            in development.
          </h4>
        </div>
      )}
      <h2>Simple Safe app on Uqbar</h2>
      <div className="card">

        <div style={{ display: "flex", flexDirection: "row", border: "1px solid gray", }} >
          <input type="text" onInput={e=>setNewSafe((e.target as HTMLInputElement).value)} value={newSafe} />
          <button onClick={e=>addSafe(newSafe)}> Add safe </button>
        </div>

        <div style={{ border: "1px solid gray", }} >
          { safes.map(safe => 
              <div> 
                { (console.log("SAFE!!!!!", safe, safe.threshold, safe.owners), <p/>)  }
                <p> { safe.address } </p>
                <p> { safe.threshold && safe.owners ? safe.threshold + "/" + safe.owners.length : null } </p> 
                <div style={{ display: "flex", flexDirection: "row", gap: "10px", border: "1px solid gray", }} >
                  <div>
                    <input type="text" onInput={e=>setNewPeer((e.target as HTMLInputElement).value)} value={newPeer} />
                    <button onClick={e=>addPeer(safe.address, newPeer )}>Add Peer</button>
                  </div>
                  <div>
                    <button onClick={e=>sendDev(safe.address, "0xB7b54cd129e6D8B24e6AE652a473449B273eE3E4")}>Send to dev</button>
                  </div>
                </div>
                <div> { safe.peers || null } </div>
                <div> txs: 
                  { safe.txs ? Object.keys(safe.txs).map(nonce => <TxComponent txs={safe.txs[nonce]}/>) : null }
                </div>
              </div>
            ) 
          } 
        </div>


      </div>
    </div>
  );
}

export default App;
