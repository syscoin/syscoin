from decimal import ROUND_UP, Decimal
import struct
from test_framework.messages import (
    ser_compact_size,
    ser_string,
)
from test_framework.blocktools import (
    SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN,
    SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION,
    SYSCOIN_TX_VERSION_ALLOCATION_MINT,
    SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM,
    SYSCOIN_TX_VERSION_ALLOCATION_SEND,
)
################################################################################
# Minimal stubs mirroring Syscoin classes:
################################################################################

DUST_THRESHOLD = Decimal('0.00000546')

def ser_varint(n):
    result = bytearray()
    while True:
        byte = n & 0x7F
        if result:
            byte |= 0x80
        result.insert(0, byte)
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
    return bytes(result)

def compress_amount_64bit(amount) -> bytes:
    if isinstance(amount, Decimal):
        amount = int(amount * 100000000)
    elif not isinstance(amount, int):
        amount = int(float(amount) * 100000000)

    if amount == 0:
        return ser_varint(0)

    e, n = 0, amount
    while (n % 10) == 0 and e < 9:
        n //= 10
        e += 1

    if e < 9:
        d = n % 10
        n //= 10
        code = 1 + (n * 9 + d - 1) * 10 + e
    else:
        code = 1 + (n - 1) * 10 + 9

    return ser_varint(code)

class AssetOutValue:
    def __init__(self, n=0, nValue=0):
        self.n = n
        self.nValue = nValue

    def serialize(self):
        return ser_compact_size(self.n) + compress_amount_64bit(self.nValue)

class AssetOut:
    def __init__(self, key=0, values=None):
        self.key = key
        self.values = values or []

    def serialize(self):
        out = ser_varint(self.key)
        out += ser_compact_size(len(self.values))
        for av in self.values:
            out += av.serialize()
        return out

class CAssetAllocation:
    def __init__(self, voutAssets=None):
        self.voutAssets = voutAssets or []

    def serialize(self):
        out = ser_compact_size(len(self.voutAssets))
        for ao in self.voutAssets:
            out += ao.serialize()
        return out

class CMintSyscoin(CAssetAllocation):
    def __init__(self, spv_proof=None):
        super().__init__()
        spv_proof = spv_proof or {}
        self.txHash = spv_proof.get("txHash", b"")
        self.txValue = spv_proof.get("txValue", b"")
        self.txPos = spv_proof.get("txPos", 0)
        self.txBlockHash = spv_proof.get("txBlockHash", b"")
        self.txParentNodes = spv_proof.get("txParentNodes", b"")
        self.txPath = spv_proof.get("txPath", b"")
        self.posReceipt = spv_proof.get("posReceipt", 0)
        self.receiptParentNodes = spv_proof.get("receiptParentNodes", b"")
        self.txRoot = spv_proof.get("txRoot", b"")
        self.receiptRoot = spv_proof.get("receiptRoot", b"")

    def serialize(self):
        out = super().serialize()
        out += self.txHash
        out += self.txValue
        out += struct.pack("<I", self.txPos)
        out += self.txBlockHash
        out += ser_string(self.txParentNodes)
        out += ser_string(self.txPath)
        out += struct.pack("<I", self.posReceipt)
        out += ser_string(self.receiptParentNodes)
        out += self.txRoot
        out += self.receiptRoot
        return out

class CBurnSyscoin(CAssetAllocation):
    def __init__(self, nevm_address=b''):
        super().__init__()
        self.vchNEVMAddress = nevm_address

    def serialize(self):
        return super().serialize() + ser_string(self.vchNEVMAddress)


################################################################################
# 3) Putting it all together in a param-based "SDK" function
################################################################################

def create_allocation_data(allocation_type: str,
                         vout_assets=None,
                         # For CMintSyscoin:
                         spv_proof=None,  # Pass the entire SPV proof as one object
                         # For CBurnSyscoin:
                         vchNEVMAddress=None
                         ) -> str:
    """Create serialized allocation data for a Syscoin transaction.
    
    Args:
        allocation_type: Type of allocation ("allocation", "mint", or "burn")
        vout_assets: List of AssetOut objects to include
        spv_proof: For mint operations, the SPV proof data (entire object)
        vchNEVMAddress: For burn operations, the NEVM address
        
    Returns:
        Hex-encoded serialized allocation data
    """
    if vout_assets is None:
        vout_assets = []
    
    if allocation_type == "allocation":
        obj = CAssetAllocation(voutAssets=vout_assets)
    
    elif allocation_type == "mint":
        obj = CMintSyscoin()
        if spv_proof:
            # Map SPV proof fields to our CMintSyscoin object
            obj.txHash = spv_proof.get("txHash", b"")
            obj.txValue = spv_proof.get("txValue", b"") 
            obj.txPos = spv_proof.get("txPos", 0)
            obj.txBlockHash = spv_proof.get("txBlockHash", b"")
            obj.txParentNodes = spv_proof.get("txParentNodes", b"")
            obj.txPath = spv_proof.get("txPath", b"")

            obj.posReceipt = spv_proof.get("posReceipt", 0)
            obj.receiptParentNodes = spv_proof.get("receiptParentNodes", b"")
            obj.txRoot = spv_proof.get("txRoot", b"")
            obj.receiptRoot = spv_proof.get("receiptRoot", b"")
        obj.voutAssets = vout_assets
    
    elif allocation_type == "burn":
        obj = CBurnSyscoin()
        if vchNEVMAddress:
            obj.vchNEVMAddress = vchNEVMAddress
        obj.voutAssets = vout_assets
    
    else:
        raise ValueError(f"Unknown allocation type: {allocation_type}")
    
    # Serialize the data
    raw_data = obj.serialize()
    return raw_data.hex()

def attach_allocation_data_to_tx(node, syscoinversion, data_hex, inputs, outputs):
    """
    Create raw tx with allocation data, then modify it with Syscoin RPC if needed
    """
    # Check if we need to handle a burn value
    burn_value = None
    if "data" in outputs and isinstance(outputs["data"], dict):
        burn_value = outputs["data"].get("value", 0)
        outputs["data"] = data_hex
        outputs["data_version"] = syscoinversion
        outputs["data_amount"] = burn_value
    
    # Clean up inputs to only include required fields
    cleaned_inputs = []
    for inp in inputs:
        cleaned_inputs.append({
            "txid": inp["txid"],
            "vout": inp["vout"]
        })
    
    # Add logging to see cleaned inputs and outputs
    print("CreateRawTransaction cleaned inputs:", cleaned_inputs)
    print("CreateRawTransaction outputs:", outputs)
    
    # Create the raw transaction
    rawtx = node.createrawtransaction(
        inputs=cleaned_inputs,
        outputs=outputs,
    )
    
    # Sign the transaction
    sign_res = node.signrawtransactionwithwallet(rawtx)
    return sign_res["hex"]

class CoinSelector:
    def __init__(self, node, max_inputs=10):
        self.node = node
        self.max_inputs = max_inputs
        self.selected_utxos = []
        self.total_sys = Decimal('0')
        self.total_assets = {}

    def analyze_utxo(self, utxo):
        sys_value = Decimal(str(utxo['amount']))
        assets = {int(asset['guid']): Decimal(str(asset['value'])) for asset in utxo.get('assets', [])}
        return sys_value, assets

    def select_optimal_inputs(self, sys_target, asset_targets=None):
        asset_targets = asset_targets or {}
        asset_targets = {int(k): v for k, v in asset_targets.items()}
        
        self.selected_utxos = []
        self.total_sys = Decimal('0')
        self.total_assets = {}

        utxos = sorted(self.node.listunspent(), key=lambda x: -x['amount'])

        for utxo in utxos:
            if len(self.selected_utxos) >= self.max_inputs:
                break

            sys_value, assets = self.analyze_utxo(utxo)
            if self.total_sys >= sys_target and all(
                self.total_assets.get(guid, 0) >= amount for guid, amount in asset_targets.items()
            ):
                break

            self.selected_utxos.append({"txid": utxo["txid"], "vout": utxo["vout"]})
            self.total_sys += sys_value
            for guid, value in assets.items():
                self.total_assets[guid] = self.total_assets.get(guid, 0) + value

        if self.total_sys < sys_target:
            raise ValueError(f"Not enough SYS: need {sys_target}, have {self.total_sys}")

        for guid, amount in asset_targets.items():
            if self.total_assets.get(guid, Decimal('0')) < amount:
                raise ValueError(f"Not enough asset {guid}: need {amount}, have {self.total_assets.get(guid, Decimal('0'))}")

    def select_coins_for_transaction(self, tx_type, sys_amount, asset_amounts=None, fees=None):
        asset_amounts = asset_amounts or {}
        asset_amounts = {int(k): v for k, v in asset_amounts.items()}

        initial_fee = fees if fees else Decimal('0.0001')
        num_asset_change_outputs = len([guid for guid in asset_amounts if asset_amounts[guid] > 0])
        total_sys_needed = sys_amount + initial_fee + (DUST_THRESHOLD * num_asset_change_outputs)

        self.select_optimal_inputs(total_sys_needed, asset_amounts)

        if self.total_sys < total_sys_needed:
            raise ValueError(f"Not enough SYS: need {total_sys_needed}, have {self.total_sys}")

        sys_change = self.total_sys - total_sys_needed
        sys_change = sys_change if sys_change >= DUST_THRESHOLD else Decimal('0')

        asset_changes = {guid: self.total_assets[guid] - asset_amounts[guid] for guid in asset_amounts if self.total_assets.get(guid, 0) > asset_amounts[guid]}

        return True, self.selected_utxos, sys_change, asset_changes

def create_transaction_with_selector(node, tx_type, sys_amount=Decimal('0'), 
                              asset_amounts=None, fees=None,
                              destinations=None, nevm_address=None,
                              spv_proof=None, destination_address=None):
    """
    Create a transaction with the specified type using CoinSelector for input selection
    
    Args:
        node: The node to use for coin selection and transaction creation
        tx_type: One of the SYSCOIN_TX_VERSION_* constants
        sys_amount: Amount of SYS to send/burn (for SYS->SYSX conversion)
        asset_amounts: Dict of {guid: amount} for asset operations
        fees: Optional override for fee calculation
        destinations: Dict of {guid: address} for asset send operations
        nevm_address: NEVM address for BURN_TO_NEVM operations
        spv_proof: SPV proof for mint operations
        destination_address: Destination address for burn/mint operations
        
    Returns:
        Hex string of the signed transaction
    """
    DUST_THRESHOLD = Decimal('0.00000546')  # Standard Bitcoin dust threshold (546 satoshis)
    
    # Initialize asset tracker for changes
    asset_outputs = []
    
    # Validate inputs based on transaction type
    if asset_amounts is None:
        asset_amounts = {}
    
    # Convert all asset keys to integers if they're strings
    asset_amounts = {int(k) if isinstance(k, str) else k: v for k, v in asset_amounts.items()}
    
    # Validate transaction type specific requirements
    if tx_type == SYSCOIN_TX_VERSION_ALLOCATION_SEND:
        if not destinations:
            raise ValueError("destinations must be provided for ALLOCATION_SEND")
    
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        if not nevm_address:
            raise ValueError("nevm_address must be provided for ALLOCATION_BURN_TO_NEVM")
        # For NEVM burns, we should only have one asset
        if len(asset_amounts) > 1:
            raise ValueError("Only one asset can be burned to NEVM in a single transaction")
    
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_MINT:
        if not spv_proof:
            raise ValueError("spv_proof must be provided for ALLOCATION_MINT")
        # For mints, we should only have one asset
        if len(asset_amounts) > 1:
            raise ValueError("Only one asset can be minted in a single transaction")
    
    elif tx_type == SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION:
        if not destination_address:
            raise ValueError("destination_address must be provided for SYSCOIN_BURN_TO_ALLOCATION")
        if sys_amount <= 0:
            raise ValueError("sys_amount must be positive for SYSCOIN_BURN_TO_ALLOCATION")
    
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN:
        if not destination_address:
            raise ValueError("destination_address must be provided for ALLOCATION_BURN_TO_SYSCOIN")
        # For SYSX->SYS, we should only have GUID 123456 (SYSX)
        if len(asset_amounts) != 1 or 123456 not in asset_amounts:
            raise ValueError("Only SYSX (GUID 123456) can be burned to SYS")
    
    # Create coin selector and select inputs
    selector = CoinSelector(node)
    if tx_type == SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION:
        success, inputs, change, asset_changes = selector.select_coins_for_transaction(
            tx_type, sys_amount, fees=fees
        )
    else:
        success, inputs, change, asset_changes = selector.select_coins_for_transaction(
            tx_type, DUST_THRESHOLD, asset_amounts, fees
        )
    
    if not success:
        raise ValueError(f"Failed to select coins for transaction type {tx_type}")
    
    # Initialize outputs as OrderedDict to maintain insertion order
    # And track output indices explicitly
    from collections import OrderedDict
    outputs = OrderedDict()
    output_indexes = {}  # Maps address -> output index
    current_output_index = 0
    
    # Start with OP_RETURN output (always first)
    # We'll fill in the actual data later
    outputs["data_placeholder"] = "placeholder"
    current_output_index += 1
    
    # Handle SYS change if any (always comes next)
    if change > 0:
        change_address = node.getnewaddress()
        outputs[change_address] = float(change)
        output_indexes[change_address] = current_output_index
        current_output_index += 1
    
    # Now add all other outputs and track their indices
    # Handle each transaction type
    if tx_type == SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION:
        # Add SYSX destination output
        outputs[destination_address] = float(DUST_THRESHOLD)
        output_indexes[destination_address] = current_output_index
        current_output_index += 1
        
        # Create SYSX output for asset data
        sysx_out = AssetOut(
            key=123456,  # GUID 123456 for SYSX
            values=[AssetOutValue(n=output_indexes[destination_address], nValue=sys_amount)]
        )
        asset_outputs.append(sysx_out)
        print(f'asset_outputs {output_indexes[destination_address]}')
        # Create OP_RETURN with burn value
        data_hex = create_allocation_data("burn", vout_assets=asset_outputs)
        # Replace placeholder with actual data
        del outputs["data_placeholder"]
        outputs["data"] = {"value": float(sys_amount), "hex": data_hex}
    
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN:
        # Add SYS destination output
        sysx_amount = asset_amounts[123456]  # We've already validated this exists
        outputs[destination_address] = float(sysx_amount)
        output_indexes[destination_address] = current_output_index
        current_output_index += 1
        
        # Create SYSX output for asset data (burn)
        # For burn to SYS, we don't need to reference a specific output in the n value
        sysx_out = AssetOut(
            key=123456,  # GUID 123456 for SYSX
            values=[AssetOutValue(n=0, nValue=sysx_amount)]
        )
        asset_outputs.append(sysx_out)
        
        # Create OP_RETURN
        data_hex = create_allocation_data("burn", vout_assets=asset_outputs)
        # Replace placeholder with actual data
        del outputs["data_placeholder"]
        outputs["data"] = data_hex
    
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        # For NEVM burn, we don't create regular outputs for the assets
        
        # Since we've validated only one asset can be burned, extract it directly
        if len(asset_amounts) != 1:
            raise ValueError("Exactly one asset must be provided for BURN_TO_NEVM")
        
        guid, amount = next(iter(asset_amounts.items()))
        
        # Create asset output for burning - use n=0 since it's being burned
        burn_out = AssetOut(
            key=int(guid),
            # For burn to NEVM, we don't need to reference a specific output
            values=[AssetOutValue(n=0, nValue=amount)]
        )
        asset_outputs.append(burn_out)
        
        # Create OP_RETURN with NEVM address
        data_hex = create_allocation_data("burn", vout_assets=asset_outputs,
                                       vchNEVMAddress=nevm_address)
        # Replace placeholder with actual data
        del outputs["data_placeholder"]
        outputs["data"] = data_hex
    
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_SEND:
        # Add all destination outputs first
        for guid, amount in asset_amounts.items():
            guid_int = int(guid)
            dest_address = destinations.get(str(guid), destinations.get(guid_int))
            if not dest_address:
                raise ValueError(f"Destination address not found for asset {guid}")
            
            # Add destination output
            outputs[dest_address] = float(DUST_THRESHOLD)
            output_indexes[dest_address] = current_output_index
            current_output_index += 1
            
            # Create asset output referencing the correct output index
            send_out = AssetOut(
                key=guid_int,
                values=[AssetOutValue(n=output_indexes[dest_address], nValue=amount)]
            )
            asset_outputs.append(send_out)
    
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_MINT:
        # Add destination output for minted assets
        outputs[destination_address] = float(DUST_THRESHOLD)
        output_indexes[destination_address] = current_output_index
        current_output_index += 1
        
        # Since we've validated only one asset can be minted, extract it directly
        if len(asset_amounts) != 1:
            raise ValueError("Exactly one asset must be provided for ALLOCATION_MINT")
        
        guid, amount = next(iter(asset_amounts.items()))
        
        # Create mint output - the asset goes to the destination output
        mint_out = AssetOut(
            key=int(guid),
            values=[AssetOutValue(n=output_indexes[destination_address], nValue=amount)]
        )
        asset_outputs.append(mint_out)
    
    # Add asset change outputs for all transaction types
    for guid, amount in asset_changes.items():
        change_address = node.getnewaddress()
        outputs[change_address] = float(DUST_THRESHOLD)
        output_indexes[change_address] = current_output_index
        current_output_index += 1
        
        change_out = AssetOut(
            key=int(guid),
            values=[AssetOutValue(n=output_indexes[change_address], nValue=amount)]
        )
        asset_outputs.append(change_out)
    
    # Create allocation data based on transaction type
    if tx_type == SYSCOIN_TX_VERSION_ALLOCATION_SEND:
        data_hex = create_allocation_data("allocation", vout_assets=asset_outputs)
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_MINT:
        data_hex = create_allocation_data("mint", vout_assets=asset_outputs, spv_proof=spv_proof)
    else:
        # Already created data_hex for burn transactions above
        pass
    
    # Replace OP_RETURN placeholder with actual data for mint and send transactions
    if tx_type in [SYSCOIN_TX_VERSION_ALLOCATION_SEND, SYSCOIN_TX_VERSION_ALLOCATION_MINT]:
        del outputs["data_placeholder"]
        outputs["data"] = data_hex
    
    # Create and sign the transaction
    tx_hex = attach_allocation_data_to_tx(node, tx_type, data_hex, inputs, outputs)
    return tx_hex

def example_multi_asset_transaction():
    """Examples of all five main Syscoin transaction types using CoinSelector"""
    node = setup_node()  # Function to set up your test node
    
    # 1. ALLOCATION_SEND: Send multiple assets to specific addresses
    asset_amounts = {
        "123456": Decimal('500'),
        "654321": Decimal('300')
    }
    destinations = {
        "123456": "sys1qxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        "654321": "sys1qyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy"
    }
    send_tx_hex = create_transaction_with_selector(
        node=node,
        tx_type=SYSCOIN_TX_VERSION_ALLOCATION_SEND,
        asset_amounts=asset_amounts,
        destinations=destinations
    )
    sign_and_send(send_tx_hex, "Sending multiple assets")
    
    # 2. ALLOCATION_MINT: Mint new assets with SPV proof
    mint_asset_amounts = {
        "789012": Decimal('1000')
    }
    spv_proof = {
        "txHash": bytes.fromhex("1234..."),  # NEVM transaction hash
        "blockHash": bytes.fromhex("5678..."),  # NEVM block hash
        "txPos": 123,  # Transaction position
        "txParentNodes": b"...",  # Merkle proof nodes
        "txPath": b"..."  # Path in Merkle tree
    }
    mint_tx_hex = create_transaction_with_selector(
        node=node,
        tx_type=SYSCOIN_TX_VERSION_ALLOCATION_MINT,
        asset_amounts=mint_asset_amounts,
        spv_proof=spv_proof,
        destination_address="sys1qzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"  # Where minted assets go
    )
    sign_and_send(mint_tx_hex, "Minting new assets")
    
    # 3. ALLOCATION_BURN_TO_NEVM: Burn assets to NEVM
    nevm_burn_amounts = {
        "123456": Decimal('200')  # Amount of asset to burn
    }
    nevm_address = "0x1234567890123456789012345678901234567890"  # NEVM destination
    nevm_burn_tx_hex = create_transaction_with_selector(
        node=node,
        tx_type=SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM,
        asset_amounts=nevm_burn_amounts,
        nevm_address=nevm_address
    )
    sign_and_send(nevm_burn_tx_hex, "Burning assets to NEVM")
    
    # 4. SYSCOIN_BURN_TO_ALLOCATION: Convert SYS to SYSX
    sys_amount = Decimal('10.0')  # Amount of SYS to convert to SYSX
    sysx_destination = "sys1qwwwwwwwwwwwwwwwwwwwwwwwwwwwww"  # Where to send the SYSX
    sys_to_sysx_tx_hex = create_transaction_with_selector(
        node=node,
        tx_type=SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION,
        sys_amount=sys_amount,
        destination_address=sysx_destination
    )
    sign_and_send(sys_to_sysx_tx_hex, "Converting SYS to SYSX")
    
    # 5. ALLOCATION_BURN_TO_SYSCOIN: Convert SYSX back to SYS
    sysx_to_sys_amounts = {
        "123456": Decimal('5.0')  # Amount of SYSX to burn
    }
    sys_destination = "sys1qvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"  # Where to send the SYS
    sysx_to_sys_tx_hex = create_transaction_with_selector(
        node=node,
        tx_type=SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN,
        asset_amounts=sysx_to_sys_amounts,
        destination_address=sys_destination
    )
    sign_and_send(sysx_to_sys_tx_hex, "Converting SYSX to SYS")
    
    def sign_and_send(tx_hex, description):
        """Helper to sign and send transaction"""
        try:
            # Sign transaction (should already be signed from create_transaction_with_selector)
            tx_id = node.sendrawtransaction(tx_hex)
            print(f"Success: {description} - TxID: {tx_id}")
            return tx_id
        except Exception as e:
            print(f"Error with {description}: {str(e)}")
            return None



def verify_tx_outputs(node, txid, tx_type, asset_details=None):
    """Efficiently verify transaction outputs based on Syscoin transaction type."""
    asset_details = asset_details or {}
    utxos = node.listunspent()
    print(f'utxos {utxos}')
    def utxo_exists(asset_guid=None, asset_amount=None, sys_amt=None):
        for utxo in utxos:
            if utxo['txid'] != txid:
                continue
            if sys_amt and Decimal(str(utxo['amount'])) != Decimal(str(sys_amt)):
                continue
            if asset_guid and asset_amount:
                for asset in utxo.get('assets', []):
                    if int(asset['guid']) == asset_guid and Decimal(str(asset['value'])) == Decimal(str(asset_amount)):
                        return True
                continue
            elif not asset_guid and not asset_amount:
                return True
        return False

    if tx_type == SYSCOIN_TX_VERSION_ALLOCATION_SEND:
        for guid, amount in asset_details.items():
            if not utxo_exists(asset_guid=guid, asset_amount=amount, sys_amt=DUST_THRESHOLD):
                raise AssertionError(f"Asset output not found: txid={txid}, guid={guid}, amount={amount}")

    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_MINT:
        for guid, amount in asset_details.items():
            if not utxo_exists(asset_guid=guid, asset_amount=amount, sys_amt=DUST_THRESHOLD):
                raise AssertionError(f"Minted asset not found: txid={txid}, guid={guid}, amount={amount}")

    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        for guid, amount in asset_details.items():
            if utxo_exists(asset_guid=guid, asset_amount=amount):
                raise AssertionError(f"Burned asset still found in UTXO: txid={txid}, guid={guid}, amount={amount}")

    elif tx_type == SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION:
        for guid, amount in asset_details.items():
            if not utxo_exists(asset_guid=guid, asset_amount=amount):
                raise AssertionError(f"SYSX output not found in UTXO: txid={txid}, guid={guid}, amount={amount}")

    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN:
        for guid, amount in asset_details.items():
            if utxo_exists(asset_guid=guid, asset_amount=amount):
                raise AssertionError(f"SYS output still found in UTXO: txid={txid}, guid={guid}, amount={amount}")
        sys_amt = list(asset_details.values())[0]
        if not utxo_exists(sys_amt=sys_amt):
            raise AssertionError(f"SYS output not found: txid={txid}, amount={sys_amt}")

    else:
        raise ValueError("Unknown transaction type")

    print(f"Verified UTXOs successfully for txid={txid}, tx_type={tx_type}")