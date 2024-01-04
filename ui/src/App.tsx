import { useState, useEffect } from "react";
import UqbarEncryptorApi from "@uqbar/client-encryptor-api";
import ConnectWallet from "./components/ConnectWallet";
import "./App.css";

const BASE_URL = import.meta.env.BASE_URL;
if (window.our) window.our.process = BASE_URL?.replace("/", "");

const PROXY_TARGET = `${(import.meta.env.VITE_NODE_URL || "http://localhost:8080")}${BASE_URL}`;

// This env also has BASE_URL which should match the process + package name
const WEBSOCKET_URL = import.meta.env.DEV
  ? `${PROXY_TARGET.replace('http', 'ws')}`
  : undefined;

function App() {
  const [selectedChat, setSelectedChat] = useState("New Chat");

  const [nodeConnected, setNodeConnected] = useState(true);
  const [api, setApi] = useState<UqbarEncryptorApi | undefined>();

  const [ connectOpen, setConnectOpen ] = useState<boolean>(false);
  const openConnect = () => setConnectOpen(true)
  const closeConnect = () => setConnectOpen(false)

  useEffect(() => {
    // Get message history using http

    // Connect to the uqbar node via websocket
    if (window.our?.node && window.our?.process) {
      const api = new UqbarEncryptorApi({
        uri: WEBSOCKET_URL,
        nodeId: window.our.node,
        processId: window.our.process,
        onOpen: (_event, _api) => {
          console.log("Connected to uqbar node");
          // api.send({ data: "Hello World" });
        },
        onMessage: (json, _api) => {
          console.log('WEBSOCKET MESSAGE', json)
          try {
            const data = JSON.parse(json);
            console.log("WebSocket received message", data);
            const [messageType] = Object.keys(data);
            if (!messageType) return;
          } catch (error) {
            console.error("Error parsing WebSocket message", error);
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
      {!nodeConnected && (
        <div className="node-not-connected">
          <h2 style={{ color: "red" }}>Node not connected</h2>
          <h4>
            You need to start a node at {PROXY_TARGET} before you can use this UI
            in development.
          </h4>
        </div>
      )}
      <ConnectWallet {...{connectOpen, closeConnect}} />
      <h2>Simple Safe app on Uqbar</h2>
      <div className="card">
        <div
          style={{
            display: "flex",
            flexDirection: "row",
            border: "1px solid gray",
          }}
        >
          <div>
            connected
          </div>
          <div
            style={{ flex: 1, borderRight: "1px solid gray", padding: "1em" }}
          >
            <h3 style={{ marginTop: 0 }}>Safes</h3>
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
