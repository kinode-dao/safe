
import { useWeb3React } from "@web3-react/core";
import { hooks, metaMask } from "../connectors/metamask";
import { useCallback, useEffect, useState } from "react";
import Loader from "./Loader";
import { setSepolia } from "../utils/chain";
import ChainInfo from "./ChainInfo";

const { useIsActivating, useChainId } = hooks;

type HeaderProps = {
    msg: string,
    openConnect: () => void,
    closeConnect: () => void
    hideConnect?: boolean,
}

function Header ({msg, openConnect, closeConnect, hideConnect = false}: HeaderProps) {
    const { account, isActive } = useWeb3React()
    const isActivating = useIsActivating();
    const chainId = useChainId();

    const [networkName, setNetworkName] = useState('');

    useEffect(() => {
        setNetworkName(getNetworkName((chainId || 1).toString()));
    }, [chainId]);

    const getNetworkName = (networkId: string) => {
        switch (networkId) {
            case '1':
                return 'Ethereum'; // Ethereum Mainnet
            case '10':
                return 'Optimism'; // Optimism
            case '42161':
                return 'Arbitrum'; // Arbitrum One
            case '11155111':
                return 'Sepolia'; // Sepolia Testnet
            default:
                return 'Unknown';
        }
    };

    const connectWallet = useCallback(async () => {
        closeConnect()
        await metaMask.activate().catch(() => {})

        try {
          setSepolia()
        } catch (error) {
          console.error(error)
        }
    }, [closeConnect]);

    const changeToSepolia = useCallback(async () => {
        // If Sepolia is set, just show a message
        if (networkName === 'Sepolia') {
            alert('You are already connected to Sepolia');
            return;
        }

        try {
            setSepolia()
        } catch (error) {
            console.error(error)
        }
    }, [networkName]);

    const changeConnectedAccount = useCallback(async () => {
        alert('You can change your connected account in your wallet.')
    }, []);

    // <div style={{ textAlign: 'center', lineHeight: 1.5 }}> Connected as {account?.slice(0,6) + '...' + account?.slice(account.length - 6)}</div>
    return (
        <>
            <div id="signup-form-header" className="col" >
                <h1 style={{textAlign: "center"}}> { msg } </h1>
                {!hideConnect && <div style={{ minWidth: '50vw', width: 400, justifyContent: 'center', display: 'flex', }}>
                    { isActive && account
                        ? ( <div/>
                            // <ChainInfo
                            //     account={account}
                            //     networkName={networkName}
                            //     changeToSepolia={changeToSepolia}
                            //     changeConnectedAccount={changeConnectedAccount}
                            // />
                        ) : (
                            <div className="col">
                                <div style={{ textAlign: 'center', lineHeight: '1.5em' }}>You must connect to a browser wallet to continue</div>
                                {/* <div style={{ textAlign: 'center', lineHeight: '1.5em' }}>We recommend <a href="https://metamask.io/download.html" target="_blank" rel="noreferrer">MetaMask</a></div> */}
                                {isActivating ? (
                                    <Loader msg="Approve connection in your wallet" />
                                ) : (
                                    <button onClick={connectWallet}> Connect Wallet </button>
                                )}
                                <div style={{ textAlign: 'center', lineHeight: '1.5em', fontSize: '0.8em', marginTop: '2em' }}>
                                    Uqbar is currently on the Sepolia Testnet, if you need testnet ETH, you can get some from the <a href="https://sepoliafaucet.com/" target="_blank" rel="noreferrer">Sepolia Faucet</a>
                                </div>
                            </div>
                        )
                    }
                </div>}
            </div>
        </>
    )
}

export default Header
