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

const { useProvider, useIsActivating, useChainId } = hooks;

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
  const provider = useProvider();

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
      body: JSON.stringify({ AddSafeFE: checksum })
    })

  }

  const sendDev = async (safe, to) => {

    console.log("sending to dev")
    let response = await fetch(`${BASE_URL}/safe/tx`, { 
      method: "POST", 
      body: JSON.stringify({ AddTxFE: [safe, to, 1] })
    })

    console.log("resposne", response);
    let json = await response.json();
    console.log("json", json);

  }

  const addPeer = async (safe, peer) => {
    await fetch(`${BASE_URL}/safe/peer`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({AddPeersFE:[safe, [peer]]})
    })
  }

  const signTx = async (safe, tx) => {

    const EIP712_SAFE_TX_DOMAIN = { 
      chainId: chainId, 
      verifyingContract: safe 
    };

    // "SafeTx(address to,uint256 value,bytes data,uint8 operation,uint256 safeTxGas,uint256 baseGas,uint256 gasPrice,address gasToken,address refundReceiver,uint256 nonce)"
    const EIP712_SAFE_TX_TYPE = {
      SafeTx: [
          { type: "address", name: "to" },
          { type: "uint256", name: "value" },
          { type: "bytes", name: "data" },
          { type: "uint8", name: "operation" },
          { type: "uint256", name: "safeTxGas" },
          { type: "uint256", name: "baseGas" },
          { type: "uint256", name: "gasPrice" },
          { type: "address", name: "gasToken" },
          { type: "address", name: "refundReceiver" },
          { type: "uint256", name: "nonce" },
      ],
    };

    const EIP712_SAFE_TX_VALUE = {
        to: tx.to,
        value: BigInt(tx.value),
        data: tx.data,
        operation: BigInt(tx.operation),
        safeTxGas: BigInt(tx.safe_tx_gas),
        baseGas: BigInt(tx.base_gas),
        gasPrice: BigInt(tx.gas_price),
        gasToken: tx.gas_token,
        refundReceiver: tx.refund_receiver,
        nonce: BigInt(tx.nonce)
    }

    const signer = await provider.getSigner();
    const addr = await signer.getAddress();
    const sig = await signer._signTypedData(
      EIP712_SAFE_TX_DOMAIN, 
      EIP712_SAFE_TX_TYPE, 
      EIP712_SAFE_TX_VALUE
    );

    const sig_response = await fetch(`${BASE_URL}/safe/tx/sign`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        AddTxSigFE:[safe, tx.nonce, tx.originator, tx.timestamp, addr, sig]
      })
    })

  }

  const sendTx = async (safe, tx) => {

    const send_response = await fetch(`${BASE_URL}/safe/tx/send`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        SendTxFE:[safe, tx.nonce, tx.originator, tx.timestamp]
      })
    })

  }

  // bootstrap
  useEffect(() => { (async() => {

    let safes = await (await fetch(`${BASE_URL}/safes`, { method: "GET" })).json();

    setSafes(Object.values(safes))

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

                  const safe = JSON.parse(event.target.result)["UpdateSafe"];
                  console.log("safe", safe)
                  setSafes(prevSafes => {
                    console.log("prevsafes", prevSafes[0])
                    let indx = prevSafes.findIndex(s => s.address == safe.address);
                    return indx != -1
                      ? [ ...prevSafes.slice(0, indx), safe, ...prevSafes.slice(indx + 1) ]
                      : [ ...prevSafes, safe ];
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

  const TxComponent = ({txs, safe}: {txs: SafeTx[], safe: string}) => {
    return (
      <div key={txs[0].nonce}>
        <div> Nonce: {txs[0].nonce} </div>
        { txs.map(tx => 
          <div key={tx.timestamp}>
            <p> To: {tx.to} </p>
            <p> Value: {tx.value } </p>
            <button onClick={e=> signTx(safe, tx)}> Sign </button>
            <button onClick={e=> sendTx(safe, tx)}> Send </button>
            { tx.signatures.map((sig,ix) => <p key={ix}> { "✅ " + sig.peer} </p>) } 
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
              <div key={safe.address}> 
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
                  { safe.txs ? Object.keys(safe.txs).map(nonce => <TxComponent key={nonce} safe={safe.address} txs={safe.txs[nonce]}/>) : null }
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
