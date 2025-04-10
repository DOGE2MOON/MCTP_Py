# MCTP_Py
Mayan [MCTP](https://docs.mayan.finance/architecture/mctp) class written in Python

## Example Usage: bridge 10 USDC from Base to Optimism using MCTP

```python
# import the necessary packages
from MCTP_Py import MCTP, instantiate_account, instantiate_chain_dict

# (OPTIONAL) instantiate account object
keystore_path = 'path/to/encrypted/keystore'
account = instantiate_account(keystore_path)

# instantiate chain dicts
base_chain_dict = instantiate_chain_dict(
  name='base',
  rpc_url='http://your_base_rpc_provider.com',
  api_key='your_basescan_api_key'
)

# or do it yourself, ensuring the proper web3 middleware has been set
web3 = Web3(Web3.HTTPProvider('http://your_base_rpc_provider.com'))
web3.middleware_onion.inject(geth_poa_middleware, layer=0)
web3.eth.set_gas_price_strategy(rpc_gas_price_strategy)
optimism_chain_dict = {
  'NAME': 'optimism',
  'RPC': 'http://your_base_rpc_provider.com',
  'web3': web3,
  'API_KEY': 'your_optimistic_etherscan_api_key'
}

# define amount to bridge and token addresses
amount_in_human = 10 
tokenIn = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913' # Base native USDC
tokenOut = '0x0b2C639c533813f4Aa9D7837CAf62653d097Ff85' # OP native USDC

# instantiate the MCTP class using the account we made earlier
# useful if you already have an account object in your script
MCTPClient = MCTP(keystore_path=account, chain_dict=base_chain_dict)

# or pass the keystore path instead
MCTPClient = MCTP(keystore_path=keystore_path, chain_dict=base_chain_dict)

# Get a quote from the Mayan API
quote = MCTPClient.get_MCTP_quote(
  amountIn=10,
  fromToken=tokenIn,
  fromChain=base_chain_dict.name,
  toToken=tokenOut,
  toChain=optimism_chain_dict.name
)
print(quote)
# use index = 1 for cheap, index = 0 for fast
quote = quote[1]

# Send the transaction
# pass tokenInDecimals=False to fetch decimals from the contract; otherwise, pass an int
tx_receipt = MCTPClient.forwardERC20(
  quote=quote,
  chain_dict=from_chain_dict,
  tokenInDecimals=False,
  poll_latency=0.5
) 
print(tx_receipt)
```



