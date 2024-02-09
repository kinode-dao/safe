import { useState, useEffect, useCallback } from "react";
import { useWeb3React } from "@web3-react/core";
import { hooks, metaMask } from "./connectors/metamask";
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
    txs: string[],
    tx_sigs: string[],
    threshold: number
  };

  const [safes, setSafes] = useState<Safe[]>([]);
  const [newSafe, setNewSafe] = useState("");
  const [newPeer, setNewPeer] = useState("");
  const [newSigner, setNewSigner] = useState("");
  const [newDelegate, setNewDelegate] = useState("");

  const addSafe = async (safe) => {

    let response = await fetch(`${BASE_URL}/safe`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ AddSafe: safe })
    })

    if (response.status == 200) {
      setSafes(safes.concat({ address: safe, } as Safe))
    }
  }

  const sendDev = async () => {

    console.log("sending to dev")
    let response = await fetch(`${BASE_URL}/safe/send`, { method: "POST", })
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

          if (typeof json === 'string') { } 
          else {
            const reader = new FileReader();
            reader.onload = function(event) {
              if (typeof event?.target?.result === 'string') {
                try {
                  const pkt = JSON.parse(event.target.result);

                  Object.keys(pkt).forEach(key => {
                    switch (key) {
                      case "AddSafe": {
                        if (!safes.find(s => s.address == pkt[key])) {
                          setSafes(prevSafes => prevSafes
                            .concat({address: pkt[key]} as Safe))
                        }
                        break;
                      }
                      case "AddPeers": {
                        let addr = pkt[key][0]
                        let peers = pkt[key][1]
                        let indx = safes.findIndex(s => s.address == addr)
                        if (indx != -1 && !_.isEqual(safes[indx].peers, peers)) {
                            setSafes(prevSafes => prevSafes
                              .map((s,ix) => {
                                if (ix == indx)
                                  for (let peer of peers)
                                    if (!s.peers.find(p => p == peer)) 
                                      s.peers.push(peer)
                                return s
                              })
                            )
                        } else {
                          setSafes(prevSafes => prevSafes
                            .concat({address: pkt[key][0], peers: [pkt[key][1]]} as Safe))
                        }
                        break;
                      }
                      case "AddOwners": {
                        let safe = pkt[key][0]
                        let owners = pkt[key][1]
                        console.log("add owners", safe, owners)
                        let indx = safes.findIndex(s => s.address == safe.address)
                        if (indx != -1 && !_.isEqual(safes[indx].owners, owners)) {
                          setSafes(prevSafes => prevSafes
                            .map((s,ix) => { 
                              if (ix == indx) { 
                                for (let owner of owners) {
                                  if (!s.owners.find(o => o == owner)) {
                                    s.owners.push(owner)
                                  }
                                }
                              } 
                              return s 
                            })
                          )
                        }
                        break;
                      }
                      case "UpdateThreshold": {
                        let safe = pkt[key][0]
                        let threshold = pkt[key][1]
                        console.log("update threshold", safe, threshold)
                        let indx = safes.findIndex(s => s.address == safe.address)
                        setSafes(prevSafes => prevSafes
                          .map((s,ix) => ix == indx ? {...s, threshold: threshold} : s))
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

        <div style={{ display: "flex", flexDirection: "row", border: "1px solid gray", }} >
          <div style={{ flex: 1, borderRight: "1px solid gray", padding: "1em" }} >
            <h3 style={{ marginTop: 0 }}>Safes</h3>
          </div>
          { safes.map(safe => 
              <div> 
                { safe.address } 
                <div style={{ display: "flex", flexDirection: "row", border: "1px solid gray", }} >
                  <input type="text" onInput={e=>setNewPeer((e.target as HTMLInputElement).value)} value={newPeer} />
                  <button onClick={e=>addPeer(safe.address, newPeer )}>Add Peer</button>
                  <button onClick={e=>sendDev()}>Send to dev</button>
                </div>
                { safe.peers }
              </div>
            ) 
          } 
        </div>


      </div>
    </div>
  );
}

export default App;
