import { SEPOLIA_OPT_HEX, SEPOLIA_OPT_INT } from "../constants/chainId";

export const SEPOLIA_DETAILS = {
  chainId: SEPOLIA_OPT_HEX, // Replace with the correct chainId for Sepolia
  chainName: 'Sepolia Test Network',
  nativeCurrency: {
    name: 'Ethereum',
    symbol: 'ETH',
    decimals: 18
  },
  rpcUrls: ['https://sepolia-infura.brave.com/'], // Replace with Sepolia's RPC URL
  blockExplorerUrls: ['https://sepolia.etherscan.io'] // Replace with Sepolia's block explorer URL
};

export const setSepolia = async () => {
  const networkId = String(await (window.ethereum as any)?.request({ method: 'net_version' }).catch(() => '0x1'))

  if (networkId !== SEPOLIA_OPT_HEX && networkId !== SEPOLIA_OPT_INT) {
    await (window.ethereum as any)?.request({
      method: 'wallet_addEthereumChain',
      params: [SEPOLIA_DETAILS]
    })
  }
}
