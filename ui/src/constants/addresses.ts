import { ChainId } from './chainId'

type AddressMap = { [chainId: string]: string }

export const QNS_REGISTRY_ADDRESSES : AddressMap = {
    [ChainId.SEPOLIA]: '0x4C8D8d4A71cE21B4A16dAbf4593cDF30d79728F1',
}

export const DOT_UQ_ADDRESSES : AddressMap = {
    [ChainId.SEPOLIA]: '0x9354E3b14A99a5Be5e2f0edB825681186C15BA62'
}
