#!/usr/bin/env python3

import json
import requests
from decimal import Decimal
from test_framework.asset_helpers import (
    create_transaction_with_selector,
    verify_tx_outputs,
    SYSCOIN_TX_VERSION_ALLOCATION_MINT,
)
from test_framework.util import (
    assert_equal
)
RPC_USER = 'u'
RPC_PASSWORD = 'p'
RPC_URL = 'http://127.0.0.1:18370'  # Syscoin Testnet RPC
SYSX_GUID = 123456
DUST_THRESHOLD = Decimal('0.00000546')
BLOCK_REWARD = Decimal('50')
def syscoin_tx(node, tx_type, asset_amounts, sys_amount=Decimal('0'), sys_destination=None, nevm_address=None, spv_proof=None):
    tx_hex = create_transaction_with_selector(
        node=node,
        tx_type=tx_type,
        sys_amount=sys_amount,
        sys_destination=sys_destination,
        asset_amounts=asset_amounts,
        nevm_address=nevm_address,
        spv_proof=spv_proof
    )
    txid = node.sendrawtransaction(tx_hex)
    node.generate(1)
    # Verify the transaction outputs
    verify_tx_outputs(
        node=node,
        txid=txid, 
        tx_type=tx_type,
        asset_details=asset_amounts
    )
    return txid

def allocation_mint(node, asset_amounts, spv_proof, sys_amount=Decimal('0'), sys_destination=None):
    txid = syscoin_tx(node, SYSCOIN_TX_VERSION_ALLOCATION_MINT, asset_amounts, sys_amount, sys_destination, spv_proof=spv_proof)
    return txid

def rpc_call(method, params=None):
    headers = {'content-type': 'application/json'}
    auth = (RPC_USER, RPC_PASSWORD)
    payload = {
        "method": method,
        "params": params or [],
        "jsonrpc": "2.0",
        "id": "1"
    }
    response = requests.post(RPC_URL, auth=auth, headers=headers, data=json.dumps(payload))
    result = response.json()
    if 'error' in result and result['error']:
        raise Exception(f"RPC Error: {result['error']}")
    return result['result']

class NodeRPC:
    def listunspent(self):
        return rpc_call('listunspent')

    def createrawtransaction(self, inputs, outputs):
        return rpc_call('createrawtransaction', [inputs, outputs])

    def signrawtransactionwithwallet(self, raw_tx):
        return rpc_call('signrawtransactionwithwallet', [raw_tx])

    def sendrawtransaction(self, tx_hex):
        return rpc_call('sendrawtransaction', [tx_hex])

    def getnewaddress(self):
        return rpc_call('getnewaddress')

    def getbalance(self):
        return Decimal(str(rpc_call('getbalance')))

    def generate(self, nblocks):
        return rpc_call('generatetoaddress', [nblocks, self.getnewaddress(), 1000000000])

if __name__ == "__main__":
    node = NodeRPC()

    # Your SPV proof data (already prepared)
    spv_proof = {
        "txHash": bytes.fromhex("c7bb86858fdc4c31b3a6d6e6d10eb3c5898361588eb7d1c670e97f211a935394"),
        "txPos": 13,
        "txBlockHash": bytes.fromhex("db83a3112b2de0eab4a5ba33781b4f771e721ef8e908b5fcf62ca512b946dea3"),
        "txRoot": bytes.fromhex("80f9f7cc8e2acc7e6be99e3cd5a25ae08b635f5800a54730e6c3be6fe4dac403"),
        "txParentNodes": bytes.fromhex("f9015ef9015b822080b9015502f9015182164455839896808407270e00837a120094ac58ee0585ed36b1529ab59393a575102bf8b5f780b8e4ab972f5a000000000000000000000000000000000000000000000000000000000000000a000000000000000000000000cfc70174879f01537010c85c485b37166f03f8e300000000000000000000000000000000000000000000000000000000000003090000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000002c74737973317177386e397a7134796e716e393473706b30767173717066756b726e32736a75716635616563700000000000000000000000000000000000000000c080a0f5ecb2cef7946dc20012ca52545d21c41fe7cf8fb373c836f92550f4d7673365a073deaafb53a5958344a08a1e0fdafab51055c591c32e8d42d044fff5f21fc461"),
        "txPath": bytes.fromhex("80"),
        "receiptRoot": bytes.fromhex("b64cfc6d8a5e9dc54bb262ae0cfa1383fbbe0b62e8a537bfd6c9e96853b6f098"),
        "receiptParentNodes": bytes.fromhex("f903b3f903b0822080b903aa02f903a60183029ceeb901000000000000400000000000000000000000000000000000800000000000000000000000000000800000000000000000000000100002000010000000002000200000000000000000000000000000000000000020000000000000000000c000000000100000000000000000000000000000000000000000000100000400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000000800000000000000000400004000000000000000000800000000080000020008408200000000000000000000000000000000000000000000000000000000000000000000000081000000000f9029bf89b94ac58ee0585ed36b1529ab59393a575102bf8b5f7f842a08b803ac4bafd549786ec90c18b77168e378826e9d960830a680c85ba0247d430a00000000000000000000000000000000000000000000000000000000000000003b840000000000000000000000000cfc70174879f01537010c85c485b37166f03f8e30000000000000000000000000000000000000000000000000000000000000004f8dd94cfc70174879f01537010c85c485b37166f03f8e3f884a0c3d58168c5ae7397731d063d5bbf3d657854427343f4c083240f7aacaa2d0f62a0000000000000000000000000ac58ee0585ed36b1529ab59393a575102bf8b5f7a0000000000000000000000000bd244ffc1e6c64a6732f2b5b123d1e34d43ec341a0000000000000000000000000ac58ee0585ed36b1529ab59393a575102bf8b5f7b8400000000000000000000000000000000000000000000000000000000000000309000000000000000000000000000000000000000000000000000000000000000af9011c94ac58ee0585ed36b1529ab59393a575102bf8b5f7f863a00b8914e27c9a6c88836bc5547f82ccf331142c761f84e9f1d36934a6a31eefada00000000000000000000000000000000000000000000000000000000100000003a0000000000000000000000000bd244ffc1e6c64a6732f2b5b123d1e34d43ec341b8a0000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000000000000000000000000000000000040000000000000000000000000000000000000000000000000000000000000002c74737973317177386e397a7134796e716e393473706b30767173717066756b726e32736a75716635616563700000000000000000000000000000000000000000"),
        "posReceipt": 13,
    }
    

    asset_guid = 4294967299
    amount = Decimal('10') / Decimal('1e8')
    destination = "tsys1qw8n9zq4ynqn94spk0vqsqpfukrn2sjuqf5aecp"

    asset_amounts = [
        (asset_guid, amount, destination)
    ]
    txid = allocation_mint(node, asset_amounts, spv_proof)
    print(f"Transaction broadcasted successfully, TXID: {txid}")
