import json
import requests
import time
import getpass
from web3 import Web3
from web3.middleware import local_filter_middleware, geth_poa_middleware, construct_sign_and_send_raw_middleware
#from web3.gas_strategies.time_based import fast_gas_price_strategy, construct_time_based_gas_price_strategy
from web3.gas_strategies.rpc import rpc_gas_price_strategy
import eth_account
from eth_account.messages import encode_typed_data
from eth_abi import encode as abi_encode
from eth_abi import decode

erc_abi = json.loads('[ { "constant": true, "inputs": [], "name": "name", "outputs": [ { "name": "", "type": "string" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": false, "inputs": [ { "name": "_spender", "type": "address" }, { "name": "_value", "type": "uint256" } ], "name": "approve", "outputs": [ { "name": "", "type": "bool" } ], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": true, "inputs": [], "name": "totalSupply", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": false, "inputs": [ { "name": "_from", "type": "address" }, { "name": "_to", "type": "address" }, { "name": "_value", "type": "uint256" } ], "name": "transferFrom", "outputs": [ { "name": "", "type": "bool" } ], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": true, "inputs": [], "name": "decimals", "outputs": [ { "name": "", "type": "uint8" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [ { "name": "_owner", "type": "address" } ], "name": "balanceOf", "outputs": [ { "name": "balance", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": true, "inputs": [], "name": "symbol", "outputs": [ { "name": "", "type": "string" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "constant": false, "inputs": [ { "name": "_to", "type": "address" }, { "name": "_value", "type": "uint256" } ], "name": "transfer", "outputs": [ { "name": "", "type": "bool" } ], "payable": false, "stateMutability": "nonpayable", "type": "function" }, { "constant": true, "inputs": [ { "name": "_owner", "type": "address" }, { "name": "_spender", "type": "address" } ], "name": "allowance", "outputs": [ { "name": "", "type": "uint256" } ], "payable": false, "stateMutability": "view", "type": "function" }, { "payable": true, "stateMutability": "payable", "type": "fallback" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "owner", "type": "address" }, { "indexed": true, "name": "spender", "type": "address" }, { "indexed": false, "name": "value", "type": "uint256" } ], "name": "Approval", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": true, "name": "from", "type": "address" }, { "indexed": true, "name": "to", "type": "address" }, { "indexed": false, "name": "value", "type": "uint256" } ], "name": "Transfer", "type": "event" } ]')

## helper functions
def instantiate_web3_http(rpc_url):
	# return web3 object with desired middleware
	web3 = Web3(Web3.HTTPProvider(rpc_url))
	web3.middleware_onion.inject(geth_poa_middleware, layer=0)
	web3.eth.set_gas_price_strategy(rpc_gas_price_strategy)

	return web3

def instantiate_chain_dict(name: str, rpc_url: str, api_key: str):
	# return chain_dict with web3 object and block explorer API key
	chain_dict = {}
	chain_dict['NAME'] = str(name).lower()
	chain_dict['RPC'] = str(rpc_url)
	chain_dict['web3'] = instantiate_web3_http(str(rpc_url))
	chain_dict['API_KEY'] = str(api_key)

	return chain_dict

def instantiate_account(keystore_path):
	# return account object from encrypted keystore
	temp_w3 = Web3(Web3.HTTPProvider('https://eth.llamarpc.com'))
	with open(keystore_path) as keyfile:
		encrypted_key = keyfile.read()
		pw = getpass.getpass('Keystore Password: ')
		private_key = temp_w3.eth.account.decrypt(encrypted_key, pw)
		account = temp_w3.eth.account.from_key(private_key)

	return account

def api_get_abi(address: str, chain_id: int, api_key: str):
	## return the ABI of verified contracts using block explorer API
	## address = str; checksum formatted address of the contract address to query
	## chain_id = int; used to select block explorer base API url
	## api_key = str; block explorer API key

	block_explorer_dict = {
	1: "https://api.etherscan.io/api", # ethereum
	10: "https://api-optimistic.etherscan.io/api", #op
	56: "https://api.bscscan.com/api", # bsc
	137: "https://api.polygonscan.com/api",
	250: "https://api.ftmscan.com/api", # ftm
	42161: "https://api.arbiscan.io/api", # arbitrum
	8453: "https://api.basescan.org/api" # base
	}

	try:
   		res = requests.get(f'{block_explorer_dict[chain_id]}?module=contract&action=getabi&address={address}&apikey={api_key}')
   		res = res.json()
   		abi = json.loads(res['result'])
	except Exception as e:
		abi = None
		print(e)

	return abi


def decode_protocol_data_bytes(protocolDataHex):
	## helper function to return decoded protocolData for debugging
	
	# remove the function selector
	protocolData = protocolDataHex[10:]
	# convert to bytes
	protocolData = Web3.to_bytes(hexstr=protocolData)
	# decode using abi
	types = ['address', 'uint256', 'uint64', 'uint64', 'bytes32', 'uint32', 'uint8', 'bytes']
	decoded = decode(types, protocolData, strict=True)
	
	#print(decoded)

	return list(decoded)

def sign_permit(account, chain_dict: dict, token_address: str, spender: str, value: int):
	## Create a signed EIP-2612 permit
	
	## account: web3 account object
	## token_address: address of the token being approved (USDC, WETH, etc)
	## spender: contract address being approved to spend tokens (router contract)
	## value: Amount of tokens to approve
	## deadline: Timestamp when the permit expires (default: 1 hour from now)

	# instantiate variables
	web3 = chain_dict['web3']
	owner = Web3.to_checksum_address(account.address)
	spender = Web3.to_checksum_address(spender)
	chain_id = web3.eth.chain_id
	deadline = int(time.time() + 3600)  # 1 hour from now

	# USDC abi (token must support nonces() function)
	abi = json.loads('[{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"owner","type":"address"},{"indexed":true,"internalType":"address","name":"spender","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Approval","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"authorizer","type":"address"},{"indexed":true,"internalType":"bytes32","name":"nonce","type":"bytes32"}],"name":"AuthorizationCanceled","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"authorizer","type":"address"},{"indexed":true,"internalType":"bytes32","name":"nonce","type":"bytes32"}],"name":"AuthorizationUsed","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_account","type":"address"}],"name":"Blacklisted","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"newBlacklister","type":"address"}],"name":"BlacklisterChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"burner","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Burn","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"newMasterMinter","type":"address"}],"name":"MasterMinterChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"minter","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"amount","type":"uint256"}],"name":"Mint","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"minter","type":"address"},{"indexed":false,"internalType":"uint256","name":"minterAllowedAmount","type":"uint256"}],"name":"MinterConfigured","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"oldMinter","type":"address"}],"name":"MinterRemoved","type":"event"},{"anonymous":false,"inputs":[{"indexed":false,"internalType":"address","name":"previousOwner","type":"address"},{"indexed":false,"internalType":"address","name":"newOwner","type":"address"}],"name":"OwnershipTransferred","type":"event"},{"anonymous":false,"inputs":[],"name":"Pause","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"newAddress","type":"address"}],"name":"PauserChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"newRescuer","type":"address"}],"name":"RescuerChanged","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"from","type":"address"},{"indexed":true,"internalType":"address","name":"to","type":"address"},{"indexed":false,"internalType":"uint256","name":"value","type":"uint256"}],"name":"Transfer","type":"event"},{"anonymous":false,"inputs":[{"indexed":true,"internalType":"address","name":"_account","type":"address"}],"name":"UnBlacklisted","type":"event"},{"anonymous":false,"inputs":[],"name":"Unpause","type":"event"},{"inputs":[],"name":"CANCEL_AUTHORIZATION_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"DOMAIN_SEPARATOR","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"PERMIT_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"RECEIVE_WITH_AUTHORIZATION_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"TRANSFER_WITH_AUTHORIZATION_TYPEHASH","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"}],"name":"allowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"approve","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"authorizer","type":"address"},{"internalType":"bytes32","name":"nonce","type":"bytes32"}],"name":"authorizationState","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"balanceOf","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_account","type":"address"}],"name":"blacklist","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"blacklister","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"burn","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"authorizer","type":"address"},{"internalType":"bytes32","name":"nonce","type":"bytes32"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"cancelAuthorization","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"authorizer","type":"address"},{"internalType":"bytes32","name":"nonce","type":"bytes32"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"cancelAuthorization","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"minter","type":"address"},{"internalType":"uint256","name":"minterAllowedAmount","type":"uint256"}],"name":"configureMinter","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"currency","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"decimals","outputs":[{"internalType":"uint8","name":"","type":"uint8"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"decrement","type":"uint256"}],"name":"decreaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"increment","type":"uint256"}],"name":"increaseAllowance","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"tokenName","type":"string"},{"internalType":"string","name":"tokenSymbol","type":"string"},{"internalType":"string","name":"tokenCurrency","type":"string"},{"internalType":"uint8","name":"tokenDecimals","type":"uint8"},{"internalType":"address","name":"newMasterMinter","type":"address"},{"internalType":"address","name":"newPauser","type":"address"},{"internalType":"address","name":"newBlacklister","type":"address"},{"internalType":"address","name":"newOwner","type":"address"}],"name":"initialize","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"string","name":"newName","type":"string"}],"name":"initializeV2","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"lostAndFound","type":"address"}],"name":"initializeV2_1","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address[]","name":"accountsToBlacklist","type":"address[]"},{"internalType":"string","name":"newSymbol","type":"string"}],"name":"initializeV2_2","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_account","type":"address"}],"name":"isBlacklisted","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"isMinter","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"masterMinter","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"_to","type":"address"},{"internalType":"uint256","name":"_amount","type":"uint256"}],"name":"mint","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"minter","type":"address"}],"name":"minterAllowance","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"name","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"}],"name":"nonces","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"owner","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"pause","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"paused","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"pauser","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"validAfter","type":"uint256"},{"internalType":"uint256","name":"validBefore","type":"uint256"},{"internalType":"bytes32","name":"nonce","type":"bytes32"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"receiveWithAuthorization","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"validAfter","type":"uint256"},{"internalType":"uint256","name":"validBefore","type":"uint256"},{"internalType":"bytes32","name":"nonce","type":"bytes32"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"receiveWithAuthorization","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"minter","type":"address"}],"name":"removeMinter","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"contract IERC20","name":"tokenContract","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"amount","type":"uint256"}],"name":"rescueERC20","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"rescuer","outputs":[{"internalType":"address","name":"","type":"address"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"symbol","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"totalSupply","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"transfer","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"}],"name":"transferFrom","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newOwner","type":"address"}],"name":"transferOwnership","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"validAfter","type":"uint256"},{"internalType":"uint256","name":"validBefore","type":"uint256"},{"internalType":"bytes32","name":"nonce","type":"bytes32"},{"internalType":"bytes","name":"signature","type":"bytes"}],"name":"transferWithAuthorization","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"from","type":"address"},{"internalType":"address","name":"to","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"validAfter","type":"uint256"},{"internalType":"uint256","name":"validBefore","type":"uint256"},{"internalType":"bytes32","name":"nonce","type":"bytes32"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"transferWithAuthorization","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_account","type":"address"}],"name":"unBlacklist","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"unpause","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_newBlacklister","type":"address"}],"name":"updateBlacklister","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_newMasterMinter","type":"address"}],"name":"updateMasterMinter","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"_newPauser","type":"address"}],"name":"updatePauser","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"address","name":"newRescuer","type":"address"}],"name":"updateRescuer","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[],"name":"version","outputs":[{"internalType":"string","name":"","type":"string"}],"stateMutability":"pure","type":"function"}]')
	contract = web3.eth.contract(address=token_address, abi=abi)
	# get contract name
	contract_name = contract.functions.name().call()
	# get contract version
	contract_version = contract.functions.version().call()
	# get contract nonce
	contract_nonce = contract.functions.nonces(owner).call()

	eip712_domain =	{
		"name": contract_name,
		"version": contract_version,
		"chainId": chain_id,
		"verifyingContract": token_address
	}

	eip2612_types = {
		"EIP712Domain": [
			{"name": "name", "type": "string"},
			{"name": "version", "type": "string"},
			{"name": "chainId", "type": "uint256"},
			{"name": "verifyingContract", "type": "address"}
			],
		"Permit": [
			{"name": "owner", "type": "address"},
			{"name": "spender", "type": "address"},
			{"name": "value", "type": "uint256"},
			{"name": "nonce", "type": "uint256"},
			{"name": "deadline", "type": "uint256"}
			]
		}

	eip2612_message = {
		"owner": owner,
		"spender": spender,
		"value": int(value),
		"nonce": int(contract_nonce),
		"deadline": int(deadline)
		}
	
	''' was used for deprecated encode_structured_data() method
	eip2612_message_old = {
		"types": {
			"EIP712Domain": [
				{"name": "name", "type": "string"},
				{"name": "version", "type": "string"},
				{"name": "chainId", "type": "uint256"},
				{"name": "verifyingContract", "type": "address"}
			],
			"Permit": [
				{"name": "owner", "type": "address"},
				{"name": "spender", "type": "address"},
				{"name": "value", "type": "uint256"},
				{"name": "nonce", "type": "uint256"},
				{"name": "deadline", "type": "uint256"}
			]
		},
		"primaryType": "Permit",
		"domain": eip712_domain,
		"message": {
			"owner": owner,
			"spender": spender,
			"value": int(value),
			"nonce": int(contract_nonce),
			"deadline": int(deadline)
		}
	}
	'''
	full_message = {
		'types': eip2612_types,
		'domain': eip712_domain,
		'message': eip2612_message
	}
	# encode the message
	encoded_message = encode_typed_data(full_message=full_message)
	
	# sign the message
	signed_message = web3.eth.account.sign_message(encoded_message, account.key)
		
	# extract signature components
	signature = signed_message.signature
	r = int.from_bytes(signature[:32], byteorder='big')
	s = int.from_bytes(signature[32:64], byteorder='big')
	v = signature[64]

	return owner, spender, value, contract_nonce, deadline, v, r, s


def submit_permit(account, chain_dict: dict, token_address: str, signature_params: dict):
	## send permit() function on-chain; allow spender to spend value of token_address
	
	## account: web3 account object
	## chain_dict = dict; dict containing relevant values (web3 object, RPC URL)
	## token_address: address of the token being approved (USDC, WETH, etc)
	## signature_params = dict; owner, spender, value, deadline, v, r, s of EIP2612 signature

	owner = signature_params['owner']
	spender = signature_params['spender']
	value = signature_params['value']
	deadline = signature_params['deadline']
	v = signature_params['v']
	r = signature_params['r']
	s = signature_params['s']

	web3 = chain_dict['web3']
	# Create a contract instance with the permit function
	slop_abi = [{"inputs":[{"internalType":"address","name":"owner","type":"address"},{"internalType":"address","name":"spender","type":"address"},{"internalType":"uint256","name":"value","type":"uint256"},{"internalType":"uint256","name":"deadline","type":"uint256"},{"internalType":"uint8","name":"v","type":"uint8"},{"internalType":"bytes32","name":"r","type":"bytes32"},{"internalType":"bytes32","name":"s","type":"bytes32"}],"name":"permit","outputs":[],"stateMutability":"nonpayable","type":"function"}]
	contract = web3.eth.contract(address=token_address, abi=slop_abi)
		
	#sender = account.address
	gas = 500000
	gas_price = web3.eth.generate_gas_price()
	nonce = web3.eth.get_transaction_count(account.address)
		
	# Build the transaction
	tx = contract.functions.permit(
		Web3.to_checksum_address(owner),
		Web3.to_checksum_address(spender),
		int(value),
		int(deadline),
		v,
		web3.to_bytes(r).rjust(32, b'\0'),
		web3.to_bytes(s).rjust(32, b'\0')
	).build_transaction({
		'from': account.address,
		'gas': gas,
		'gasPrice': gas_price,
		'nonce': nonce
	})
		
	signed_tx = web3.eth.account.sign_transaction(tx, account.key)
	tx_hash = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
	tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash, timeout=60, poll_latency=0.5)
		
	return tx_receipt



class MCTP(object):
	def __init__(self, keystore_path, chain_dict):
		# optional sleep in between RPC requests, to avoid ratelimiting
		#self.sleep = 0.1

		## the same across all chains
		self.forwarder_address = '0x337685fdaB40D39bd02028545a4FfA7D287cC3E2'
		self.forwarder_abi = api_get_abi(address=self.forwarder_address, chain_id=chain_dict['web3'].eth.chain_id, api_key=chain_dict['API_KEY'])
		
		if type(keystore_path) == str:
			# instantiate account from keystore path string
			self.account = instantiate_account(keystore_path)
		else:
			# account object passed instead of keystore path
			self.account = keystore_path
		
		self.chainNameDomainDict = {
			'ethereum': 0,
			'avalanche': 1,
			'optimism': 2,
			'arbitrum': 3,
			'solana': 5,
			'base': 6,
			'polygon': 7,
			'sui': 8,
			'unichain': 9
		}

		self.chainIdDomainDict = {
			#chainid:domain
			1: 0, #eth mainnet
			10: 2, #optimism
			137: 7, #polygon
			8453: 6, #base 
			42161: 3, # arbitrum

		}
		

	def get_MCTP_quote(self, amountIn: int, fromToken: str, fromChain: str, toToken: str, toChain: str):
		## Request an MCTP quote from the Mayan API

		## amountIn = int, amount of tokens to bridge
		## fromToken = str, address of the token to bridge from
		## fromChain = str, name of the chain to bridge from (i.e. base, optimism, solana, etc)
		## toToken = str, address of the token to receive 
		## toChain = str, name of the chain to bridge to (i.e. base, optimism, solana, etc)

		solanaProgram = 'FC4eXxkyrMPTjiYUpp4EAnkmwMbQyZ6NDCh1kfLn6vsf' #WH-SOL
		referrer = '4JCpheuyWpDwJyKb9sWTNjqgkYpd7CXVtiaZNxwpRUgw' # user SOL address
		wormhole = True
		swift = True
		mctp = True
		shuttle = False
		fastMctp = False
		onlyDirect = False
		forwarder_address = self.forwarder_address

		fromChain = fromChain.lower()
		toChain = toChain.lower()
		gasless = True

		url = f'https://price-api.mayan.finance/v3/quote?wormhole=true&swift=true&mctp=true&shuttle=false&fastMctp=false&gasless=true&onlyDirect=false&solanaProgram={solanaProgram}&forwarderAddress={self.forwarder_address}&amountIn={amountIn}&fromToken={fromToken}&fromChain={fromChain}&toToken={toToken}&toChain={toChain}&slippageBps=auto&referrer={referrer}&gasDrop=0&sdkVersion=10_4_0'
		res = requests.get(url)

		if res.status_code == 200:
			content = res.json()['quotes']
		else:
			print(f'Error in quote: {res.content}')
			content = None

		return content
	
	def get_token_list(self, fromChain: str):
		## Get token list from Mayan API

		url = f'https://price-api.mayan.finance/v3/tokens?chain={fromChain.lower()}'
		res = requests.get(url)
		if res.status_code == 200:
			content = res.json()
			content = content[fromChain]
		else:
			print(res.content)
			content = None

		return content


	def forwardERC20(self, quote: dict, chain_dict: dict, tokenInDecimals: int):
		## Call forwardERC20 method on the Mayan Forwarder contract

		## quote = dict; result of get_quote() from the Mayan API
		## chain_dict = dict; dict containing relevant values for fromChain (web3 object, RPC URL)
		## tokenInDecimals = int or bool; number of decimals that tokenIn uses, or False to fetch from the chain
		
		web3 = chain_dict['web3']
		forwarder_contract = web3.eth.contract(address=self.forwarder_address, abi=self.forwarder_abi)

		# instantiate vars from the quote to ensure accuracy
		tokenIn = web3.to_checksum_address(quote['fromToken']['contract'])
		if not tokenInDecimals:
			tokenInContract = web3.eth.contract(address=tokenIn, abi=erc_abi)
			tokenInDecimals = tokenInContract.functions.decimals().call()

		tokenOut = web3.to_checksum_address(quote['toToken']['contract'])
		toChain =quote['toChain']
		mayanProtocolAddress = web3.to_checksum_address(quote['mctpMayanContract'])
		amountIn = int(quote['effectiveAmountIn64'])
		fee_amount = int(quote['bridgeFee'])
		lockFeesOnSource = quote['lockFeesOnSource']
		redeemFee = int(quote['clientRelayerFeeSuccess'] * 10**tokenInDecimals)
		gasDrop = int(quote['gasDrop'])
		destAddr = Web3.to_bytes(hexstr=self.account.address).rjust(32, b'\0') # VERY IMPORTANT encode address as bytes32, right justify with 0s
		destDomain = self.chainNameDomainDict[toChain]
		payloadType = 1 # should always be 1 for MCTP 
		customPayload = b'' # VERY IMPORTANT encode empty bytes

		# assemble args 
		args = [tokenIn, amountIn, redeemFee, gasDrop, destAddr, destDomain, payloadType, customPayload]
		# encode as bytes
		protocolData = abi_encode(['address', 'uint256', 'uint64', 'uint64', 'bytes32', 'uint32', 'uint8', 'bytes'], args)
		# temporarily convert to HexString
		protocolDataHex = protocolData.hex()
		# append forwardERC20 function selector to HexString 
		protocolDataHex = '0x2072197f' + protocolDataHex
		# encode as bytes
		protocolData = Web3.to_bytes(hexstr=protocolDataHex)
		# sign ERC-2612 permit
		owner, spender, value, contract_nonce, deadline, v, r, s = sign_permit(account=self.account, chain_dict=chain_dict, token_address=tokenIn, spender=self.forwarder_address, value=amountIn)
		
		signature_params = {
			'owner': owner, 
			'spender': spender, 
			'value': value,
			'nonce': contract_nonce,
			'deadline': deadline,
			'v': v, 
			'r': r, 
			's': s,
		}

		function_obj = getattr(forwarder_contract.functions, 'forwardERC20')
		permit_params = [amountIn, deadline, v, web3.to_bytes(r).rjust(32, b'\0'), web3.to_bytes(s).rjust(32, b'\0')]
		function_args = [tokenIn, amountIn, permit_params, mayanProtocolAddress, protocolData]

		gas = 1000000
		gas_price = web3.eth.generate_gas_price()
		tx = {'from': self.account.address, 'nonce': web3.eth.get_transaction_count(self.account.address), 'gas': gas, 'gasPrice': gas_price}
		tx = function_obj(*function_args).build_transaction(tx)

		signed_tx = web3.eth.account.sign_transaction(tx, private_key=self.account.key)
		send_tx = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
		tx_receipt = web3.eth.wait_for_transaction_receipt(send_tx, timeout=60, poll_latency=0.5)

		return tx_receipt


''' from Mayan SDK
chains = {
	'solana': 1,
	'ethereum': 2,
	'bsc': 4,
	'polygon': 5,
	'avalanche': 6,
	'arbitrum': 23,
	'optimism': 24,
	'base': 30,
	'aptos': 22,
	'sui': 21,
	'unichain': 44,
}

evmChainIdMap = {
	1: 2,
	56: 4,
	137: 5,
	43114: 6,
	42161: 23,
	10: 24,
	8453: 30,
	130: 44,
}

evmDomainDict = {
	#chainid:domain
	1: 0, #eth mainnet
	10: 2, #optimism
	8453: 6, #base 
	43114: 1, #avalanche
	42116: 3, #avalanche

}
'''


