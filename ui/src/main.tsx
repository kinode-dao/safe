import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App.tsx'
import { Web3ReactProvider, Web3ReactHooks } from '@web3-react/core'
import { hooks as metaMaskHooks, metaMask } from './connectors/metamask'
import type { MetaMask } from '@web3-react/metamask'
import './index.css'

const connectors: [MetaMask, Web3ReactHooks][] = [
  [metaMask, metaMaskHooks],
]

ReactDOM.createRoot(document.getElementById('root')!).render(
  <Web3ReactProvider connectors={connectors}>
    <App />
  </Web3ReactProvider>
)
