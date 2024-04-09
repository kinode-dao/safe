import { useState, useEffect, useCallback } from "react";
import { useWeb3React } from "@web3-react/core";
import { hooks, metaMask } from "./connectors/metamask";
import { ethers } from "ethers";
import Modal from "react-modal"
import reactLogo from "./assets/react.svg";
import viteLogo from "./assets/vite.svg";
import NectarEncryptorApi from "@uqbar/client-encryptor-api";
import ConnectWallet from "./components/ConnectWallet";
import Header from "./components/Header";
import _ from "lodash";
import backgroundImage from "./assets/background.jpg";

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
      // NOTICE: for when this is a call. 
      // TODO: may be empty bytes in which case just a tx replacement/raw send
      // TODO: may also just be bytes, need a way to indicate that
      abi: FunctionAbi,
      abi_args: [],
  }

  type FunctionAbi = { 
    inputs: FunctionInput[],
    name: string,
    stateMutability: string,
    type: string
  }

  type FunctionInput = {
    name: string,
    type: string,
  }

  type SafeTxSig = { 
    peer: string,
    signature: string,
  }

  const [safes, setSafes] = useState<Safe[]>([]);
  const [safeIndex, setSafeIndex] = useState(0);
  const [newSafe, setNewSafe] = useState("");
  const [newPeer, setNewPeer] = useState("");
  const [newSigner, setNewSigner] = useState("");
  const [newDelegate, setNewDelegate] = useState("");

  const [to, setTo] = useState("0xC5a939923E0B336642024b479502E039338bEd00");
  const [value, setValue] = useState(0);
  const [jsonAbi, setJsonAbi] = useState([]);
  const [jsonAbiIndex, setJsonAbiIndex] = useState("0");
  const [jsonAbiArgs, setJsonAbiArgs] = useState([]);
  const [buildingTx, setBuildingTx] = useState(false);
  const buildTxModal = () => setBuildingTx(true);
  const doneTxModal = () => setBuildingTx(false);

  const setJsonAbiWithIndex = (e) => {
    const indx = e.target.value;
    setJsonAbiIndex(indx)
    setJsonAbiArgs(new Array(jsonAbi[indx].inputs.length))
  }

  const setJsonAbiArgsAtIndex = (e, ix) => {
    setJsonAbiArgs(old => [
      ...old.slice(0, ix),
      e.target.value,
      ...old.slice(ix+1)
    ])
  }

  const addSafe = async (safe) => {

    const checksum = ethers.getAddress(safe);

    let response = await fetch(`${BASE_URL}/safe`, {
      method: "POST",
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ AddSafeFE: checksum })
    })

  }

  const sendDev = async (safe, to) => {

    let response = await fetch(`${BASE_URL}/safe/tx`, { 
      method: "POST", 
      body: JSON.stringify({ AddTxFE: [safe, to, 1] })
    })

    let json = await response.json();

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

    console.log("SAFES!", safes)

    setSafes(Object.values(safes))

  })()}, []);

  useEffect(() => { (async () => {
    if (ethers.isAddress(newSafe)) {

      const addr = ethers.getAddress(newSafe)
      let indx = safes.findIndex(safe => safe.address == addr)

      if (indx == -1) {
        let response = await fetch(`${BASE_URL}/safe`, {
          method: "POST",
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ AddSafeFE: addr })
        })
      } else {
        setSafeIndex(indx)
      }

    }
  })()}, [newSafe]);

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

                const json = JSON.parse(event.target.result);

                if (json["UpdateSafe"]) {

                  try {

                    const safe = json["UpdateSafe"];
                    setSafes(prevSafes => {
                      let indx = prevSafes.findIndex(s => s.address == safe.address);
                      return indx != -1
                        ? [ ...prevSafes.slice(0, indx), safe, ...prevSafes.slice(indx + 1) ]
                        : [ ...prevSafes, safe ];
                    })

                  } catch (error) {
                    console.error("Error parsing WebSocket message", error);
                  }

                } else {

                  console.log("message", json);

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

  const buildTx = async (safe, to, value, abi, inputs) => {

    const pterodactyl = ethers.dnsEncode("bronzeemperor.os")

    console.log("pt", pterodactyl)

    const body = JSON.stringify({ BuildTxFE: [
      safe.address,
      to,
      value,
      abi,
      inputs
    ] });

    let response = await fetch(`${BASE_URL}/safe/tx/build`, { 
      method: "POST",
      body: body
    });

  }

  const jsonAbiUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return
    const reader = new FileReader();
    reader.onload = async (e) => {
      const text = e.target?.result;
      try {
        const data = JSON.parse(text as string);
        setJsonAbi(data.abi ? data.abi : data);
      } catch (err) {
        console.log("err", err);
      }
    }
    reader.readAsText(file)
  }

  const txBuilderStyles = {
    content: {
      top: "50%",
      left: "50%",
      right: "auto",
      bottom: "auto",
      marginRight: "-50%",
      transform: "translate(-50%, -50%)",
      width: "80%",
      height: "80%",
      display: "flex",
      flexDirection: "column",
      justifyContent: "center",
      alignItems: "center",
      border: "1px solid black",
      padding: "20px",
      color: "white",
      backgroundColor: "#353535",
      background: `url(${backgroundImage}) no-repeat center center fixed`,
    },
    overlay: {
      backgroundColor: "transparent",
    }
  }
  interface TxBuilderProps { safe: Safe; }
  const TxBuilder = ({safe}: TxBuilderProps) => {
    return (
      <div>
        <p>Building Tx!</p>
        <p> 
          <label htmlFor="to"> To </label>
          <input type="text" id="to" value={to} onChange={(e) => setTo(e.target.value) }/>
        </p>
        <p> 
          <label htmlFor="value"> Value </label>
          <input type="number" id="to" value={value} onChange={(e) => setValue(Number(e.target.value)) }/>
        </p>
        <p>
          <label htmlFor="jsonAbi">Upload ABI</label> <br/>
          <input type="file" id="jsonAbi" onChange={jsonAbiUpload}/>
        </p>
        { jsonAbi ?
          <div> 
            Select From:
            <select value={jsonAbiIndex} onChange={setJsonAbiWithIndex}>
            { jsonAbi.map((item, ix) => 
                item.type == "function" ?
                  <option key={ix} value={ix}> 
                    { item.name }
                    { item.inputs.length ? "(" : null }
                    { item.inputs.length 
                      ? item.inputs.map((input, indx) => 
                          <span>
                            { input.name ? input.name + " ": null }
                            { input.type }
                            { indx != item.inputs.length - 1 ? ',  ' : null } 
                          </span>
                        )
                      : null
                    }
                    { item.inputs.length ? ")" : null }
                  </option> : null
              )
            }
            </select>
            { jsonAbi[jsonAbiIndex] ? 
                <p>
                  { jsonAbi[jsonAbiIndex].name }
                  { jsonAbi[jsonAbiIndex].inputs.map((input, ix) => 
                    <>
                      <label> { input.name ? input.name : input.type } </label>
                      <input value={jsonAbiArgs[ix]} placeholder={input.type} onChange={(e) => setJsonAbiArgsAtIndex(e, ix)} /> 
                    </>
                  )}
                </p> : null
            }
          </div>
          : null
        }
        <button onClick={()=> buildTx(safe, to, value, jsonAbi[jsonAbiIndex], jsonAbiArgs)}> Build Tx </button>
      </div>
    )
  }

  const TxComponent = ({txs, safe}: {txs: SafeTx[], safe: string}) => {
    return (
      <div key={txs[0].nonce}>
        <div> Nonce: {txs[0].nonce} </div>
        { txs.map(tx => 
          <div key={tx.timestamp}>
            <p> To: {tx.to} </p>
            <p> Value: {tx.value } </p>
            { tx.abi ? 
              <div> Call: { tx.abi.name + ( tx.abi.inputs ? "(" + tx.abi.inputs.map(input=> input.type) + ")" : "" ) }
                <div style={{"paddingLeft": "10px"}}> 
                  { tx.abi ? tx.abi.inputs.map((input, ix) => 
                    <p key={ix}>
                      { input.name ? input.name + ": " : "" }
                      { tx.abi_args[ix] }
                    </p> 
                  ) : null }

                </div>
              </div>
             : null }
            <p> Created By: { tx.originator } </p>
            <p> Created At: { tx.timestamp } </p>
            <button onClick={e=> signTx(safe, tx)}> Sign </button>
            <button onClick={e=> sendTx(safe, tx)}> Send </button>
            { tx.signatures.map((sig,ix) => <p key={ix}> { "✅ " + sig.peer} </p>) } 
          </div>
        ) }
      </div>
    )
  }

  const safe = safes[safeIndex]

  console.log("safe", safe)

  return (
    <div style={{ width: "100%" }}>

      <div style={{ position: "absolute", top: 4, left: 8 }}>
        ID: <strong>{window.our?.node}</strong>
      </div>

      <Header {...{openConnect, closeConnect, msg: "Kinode Safe" }} />

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

      <div>
        {/* <div style={{ padding: "25px", width: "75%", display: "flex", flexDirection:"row", justifyContent: "center", margin: "0 auto" }} >
          <input 
            type="text" 
            placeholder="Select Safe" 
            value={newSafe} 
            onInput={e=>setNewSafe((e.target as HTMLInputElement).value)} 
          />
          <button onClick={e=>addSafe(newSafe)}> Select Safe </button>
        </div> */}

        { safe ? 
          <div style={{ border: "1px solid gray", }} >
            <div style={{display: "flex", flexDirection: "row", alignItems: "center", justifyContent: "center" }}> 
              <div style={{width: "50%"}}> 
                <p> { safe.address } </p>
                <p> { safe.threshold && safe.owners ? safe.threshold + "/" + safe.owners.length : null } </p> 
                <p> { safe.peers || null } </p>
                <div style={{ display: "flex", flexDirection: "row", gap: "10px", border: "1px solid gray", }} >
                  <div>
                    <input type="text" onInput={e=>setNewPeer((e.target as HTMLInputElement).value)} value={newPeer} />
                    <button onClick={e=>addPeer(safe.address, newPeer )}>Add Peer</button>
                  </div>
                </div>
                <div>
                  <button onClick={buildTxModal}> Build Tx </button>
                  <Modal style={txBuilderStyles} isOpen={buildingTx} onRequestClose={doneTxModal}>
                    <TxBuilder safe={safe} />
                  </Modal>
                </div>
              </div>
              <div style={{width: "50%"}}> 
                txs: 
                { safe.txs ? Object.keys(safe.txs).map(nonce => <TxComponent key={nonce} safe={safe.address} txs={safe.txs[nonce]}/>) : null }
              </div>
            </div>
          </div> : null 
        }
        

      </div>
    </div>
  );
}

export default App;
