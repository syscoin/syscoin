from decimal import ROUND_UP, Decimal
import struct
SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN = 128
SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION = 129
SYSCOIN_TX_VERSION_ALLOCATION_MINT = 133
SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM = 134
SYSCOIN_TX_VERSION_ALLOCATION_SEND = 135

from test_framework.messages import (
    ser_compact_size,
    ser_string,
)
################################################################################
# Minimal stubs mirroring Syscoin classes:
################################################################################

def ser_varint(n):
    """Serialize integer using Syscoin VarInt encoding."""
    result = bytearray()
    while True:
        byte = n & 0x7F
        if len(result):
            byte |= 0x80
        result.insert(0, byte)
        if n <= 0x7F:
            break
        n = (n >> 7) - 1
    return bytes(result)

class AssetOutValue:
    """
    Python equivalent to:
       (compactSize) -> n
       (compressed amount) -> nValue
    """
    def __init__(self, n=0, nValue=0):
        self.n = n           # 32-bit index
        self.nValue = nValue # 64-bit amount

    def serialize(self, compress_amount_callback) -> bytes:
        """Write `n` as a compactSize, then `nValue` via compress_amount_callback()."""
        out = b""
        out += ser_compact_size(self.n)
        out += compress_amount_callback(self.nValue)
        return out


class AssetOut:
    """
    Python equivalent to:
       (varint) key
       (vector of AssetOutValue)
    """
    def __init__(self, key=0, values=None):
        if values is None:
            values = []
        self.key = key
        self.values = values

    def serialize(self, compress_amount_callback) -> bytes:
        out = b""
        # key is varint
        out += ser_varint(self.key)
        # 'values' is a vector of AssetOutValue
        out += ser_compact_size(len(self.values))
        for av in self.values:
            out += av.serialize(compress_amount_callback)
        return out


class CAssetAllocation:
    """
    Python version of:
      CAssetAllocation { std::vector<CAssetOut> voutAssets; }
    """
    def __init__(self, voutAssets=None):
        if voutAssets is None:
            voutAssets = []
        self.voutAssets = voutAssets

    def serialize(self, compress_amount_callback) -> bytes:
        out = b""
        out += ser_compact_size(len(self.voutAssets))
        for ao in self.voutAssets:
            out += ao.serialize(compress_amount_callback)
        return out

    def serialize_data(self, compress_amount_callback):
        # mirrors "SerializeData(std::vector<unsigned char>)" from C++ code
        return self.serialize(compress_amount_callback)


################################################################################
# Example for CMintSyscoin and CBurnSyscoin
################################################################################

class CMintSyscoin(CAssetAllocation):
    """
    Represents the mint transaction for Syscoin assets.
    Contains SPV proof data for validation.
    """
    def __init__(self):
        super().__init__()
        self.txHash = b""                # Transaction hash on NEVM
        self.txValue = b""               # Transaction value 
        self.txPos = 0                   # Transaction position in block
        self.txBlockHash = b""           # Block hash containing the transaction
        self.txParentNodes = b""         # Merkle proof parent nodes
        self.txPath = b""                # Path in the Merkle tree
        self.posReceipt = 0              # Receipt position
        self.receiptParentNodes = b""    # Receipt parent nodes
        self.txRoot = b""                # Transaction Merkle root  
        self.receiptRoot = b""           # Receipt Merkle root

    def serialize(self, compress_amount_callback):
        # 1) Serialize base CAssetAllocation
        out = super().serialize(compress_amount_callback)
        
        # 2) Serialize SPV-proof-related fields
        out += self.txHash                       # 32 bytes
        out += self.txValue                      # Variable length
        out += struct.pack("<I", self.txPos)     # 4 bytes
        out += self.txBlockHash                  # 32 bytes 
        out += ser_string(self.txParentNodes)    # Variable length
        out += ser_string(self.txPath)           # Variable length
        out += struct.pack("<I", self.posReceipt)     # 4 bytes
        out += ser_string(self.receiptParentNodes)    # Variable length
        out += self.txRoot                       # 32 bytes
        out += self.receiptRoot                  # 32 bytes
        
        return out

    def serialize_data(self, compress_amount_callback):
        return self.serialize(compress_amount_callback)


class CBurnSyscoin(CAssetAllocation):
    """
    C++ side does:
      READWRITE(AsBase<CAssetAllocation>(obj));
      READWRITE(obj.vchNEVMAddress);
    """
    def __init__(self):
        super().__init__()
        self.vchNEVMAddress = b''

    def serialize(self, compress_amount_callback):
        out = super().serialize(compress_amount_callback)
        out += ser_string(self.vchNEVMAddress)
        return out

    def serialize_data(self, compress_amount_callback):
        return self.serialize(compress_amount_callback)


################################################################################
# 2) Compress / Decompress amount
################################################################################

def compress_amount_64bit(amount) -> bytes:
    """
    Compress a 64-bit amount according to Syscoin's implementation.
    Handles both integer and Decimal values.
    """
    # If we got a Decimal, convert to integer first (satoshis)
    if isinstance(amount, Decimal):
        amount = int(amount * 100000000)
    elif not isinstance(amount, int):
        amount = int(float(amount) * 100000000)
        
    if amount == 0:
        return ser_varint(0)

    # Follow Syscoin's compression algorithm
    e = 0
    n = amount
    while (n % 10) == 0 and e < 9:
        n //= 10
        e += 1
        
    if e < 9:
        d = n % 10
        n //= 10
        code = 1 + (n * 9 + d - 1) * 10 + e
        return ser_varint(code)
    else:
        code = 1 + (n - 1) * 10 + 9
        return ser_varint(code)


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
    raw_data = obj.serialize_data(compress_amount_64bit)
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
    """
    Generic coin selector for Syscoin transactions that handles mixed UTXOs intelligently.
    Supports all transaction types and handles UTXOs that contain both SYS and assets.
    """
    def __init__(self, node, max_inputs=10):
        """Initialize with a node and maximum number of inputs to use"""
        self.node = node
        self.max_inputs = max_inputs
        self.selected_utxos = []
        self.total_sys = Decimal('0')
        self.total_assets = {}
        
    def analyze_utxo(self, utxo):
        """Analyze a UTXO to extract SYS value and any assets it contains"""
        sys_value = Decimal(str(utxo['amount']))
        assets = {}
        
        # If UTXO has assets, extract them
        if 'assets' in utxo:
            for asset in utxo['assets']:
                guid = int(asset['guid'])
                value = Decimal(str(asset['value']))
                assets[guid] = value
                
        return sys_value, assets
            
    def select_optimal_inputs(self, sys_target, asset_targets=None):
        """
        Select UTXOs optimally to cover both SYS and asset targets
        
        Args:
            sys_target: Target amount of SYS to select
            asset_targets: Dict of {guid: amount} for assets to select
            
        Returns:
            List of selected UTXOs
        """
        if asset_targets is None:
            asset_targets = {}
        
        # Convert all keys in asset_targets to integers if they're strings
        asset_targets = {int(k) if isinstance(k, str) else k: v for k, v in asset_targets.items()}
        
        # Reset selection state
        self.selected_utxos = []
        self.total_sys = Decimal('0')
        self.total_assets = {}
        
        # Convert sys_target to Decimal if it's not already
        if not isinstance(sys_target, Decimal):
            sys_target = Decimal(str(sys_target))
        
        # Get all UTXOs
        all_utxos = self.node.listunspent()
        
        # Early return if no UTXOs are available
        if not all_utxos:
            raise ValueError("No UTXOs available for selection")
        
        # Special handling for asset targets (including SYSX - GUID 123456)
        if asset_targets:
            # Get set of needed asset GUIDs
            needed_guids = set(asset_targets.keys())
            
            # Categorize UTXOs into different buckets for prioritization
            exact_match_utxos = []      # UTXOs with exactly the assets we need (no extra)
            efficient_match_utxos = []  # UTXOs with needed assets and minimal extra
            other_match_utxos = []      # UTXOs with needed assets but many extra assets
            sys_only_utxos = []         # UTXOs with only SYS (clean UTXOs)
            other_utxos = []            # All other UTXOs
            
            for utxo in all_utxos:
                sys_value, assets = self.analyze_utxo(utxo)
                utxo_guids = set(assets.keys())
                
                # Check which needed assets this UTXO contains
                matching_guids = utxo_guids.intersection(needed_guids)
                
                if matching_guids:
                    # Has at least one needed asset
                    if utxo_guids == needed_guids:
                        # Exact match - only the assets we need
                        exact_match_utxos.append(utxo)
                    elif len(utxo_guids) <= len(needed_guids) + 2:
                        # Has needed assets with few extras (efficient)
                        efficient_match_utxos.append(utxo)
                    else:
                        # Has needed assets but many extras (less efficient)
                        other_match_utxos.append(utxo)
                elif not assets and sys_value > 0:
                    # Pure SYS UTXO
                    sys_only_utxos.append(utxo)
                else:
                    # Other UTXO (no needed assets)
                    other_utxos.append(utxo)
            
            # Sort within each category
            # For exact and efficient matches, sort by descending asset values to minimize inputs
            exact_match_utxos.sort(key=lambda x: sum(self.analyze_utxo(x)[1].get(guid, 0) for guid in needed_guids), reverse=True)
            efficient_match_utxos.sort(key=lambda x: sum(self.analyze_utxo(x)[1].get(guid, 0) for guid in needed_guids), reverse=True)
            
            # For SYS-only UTXOs, sort strategy depends on goal:
            # - If SYS target is large, prefer fewer larger UTXOs (avoid fragmentation)
            # - If SYS target is small, prefer smaller UTXOs (avoid breaking large UTXOs unnecessarily)
            if sys_target > Decimal('1.0'):  # Arbitrary threshold, adjust as needed
                # For larger SYS targets, use larger UTXOs first (descending)
                sys_only_utxos.sort(key=lambda x: x['amount'], reverse=True)
            else:
                # For smaller SYS targets, use smaller UTXOs first (ascending)
                sys_only_utxos.sort(key=lambda x: x['amount'])
            
            # Other categories sort by asset count (ascending) to minimize unnecessary asset change
            other_match_utxos.sort(key=lambda x: len(self.analyze_utxo(x)[1]))
            other_utxos.sort(key=lambda x: len(self.analyze_utxo(x)[1]))
            
            # Combine sorted categories with priority
            sorted_utxos = exact_match_utxos + efficient_match_utxos + other_match_utxos + sys_only_utxos + other_utxos
        else:
            # If we only need SYS, sort strategy depends on target amount
            if sys_target > Decimal('1.0'):  # Arbitrary threshold
                # For larger SYS targets, use larger UTXOs first (descending)
                sorted_utxos = sorted(all_utxos, key=lambda x: x['amount'], reverse=True)
            else:
                # For smaller SYS targets, use smaller UTXOs first (ascending)
                sorted_utxos = sorted(all_utxos, key=lambda x: x['amount'])
        
        # Select UTXOs until we meet all targets or run out
        for utxo in sorted_utxos:
            if len(self.selected_utxos) >= self.max_inputs:
                break
                
            sys_value, assets = self.analyze_utxo(utxo)
            
            # Determine if this UTXO helps us meet our targets
            helps_sys_target = self.total_sys < sys_target
            helps_asset_targets = False
            
            for guid, amount in assets.items():
                if guid in asset_targets and self.total_assets.get(guid, Decimal('0')) < asset_targets[guid]:
                    helps_asset_targets = True
                    break
            
            # Only add this UTXO if it helps meet at least one target or if we have no UTXOs yet
            if helps_sys_target or helps_asset_targets or not self.selected_utxos:
                # Add this UTXO to our selection
                self.selected_utxos.append(utxo)
                
                # Update SYS total
                self.total_sys += sys_value
                
                # Update asset totals
                for guid, value in assets.items():
                    if guid in self.total_assets:
                        self.total_assets[guid] += value
                    else:
                        self.total_assets[guid] = value
                
                # Check if we've met all targets
                if self.total_sys >= sys_target:
                    met_all_asset_targets = True
                    for guid, target in asset_targets.items():
                        if guid not in self.total_assets or self.total_assets[guid] < target:
                            met_all_asset_targets = False
                            break
                    
                    if met_all_asset_targets:
                        break
        
        # Check if we have enough funds
        if self.total_sys < sys_target:
            raise ValueError(f"Not enough SYS: need {sys_target}, have {self.total_sys}")
        
        for guid, target in asset_targets.items():
            if guid not in self.total_assets or self.total_assets[guid] < target:
                raise ValueError(f"Not enough asset {guid}: need {target}, have {self.total_assets.get(guid, Decimal('0'))}")
        
        return self.selected_utxos

    def add_input(self, utxo):
        """Add a UTXO to our selection and update totals."""
        self.selected_utxos.append({"txid": utxo["txid"], "vout": utxo["vout"]})
        
        # Update SYS total
        self.total_sys += Decimal(utxo['amount'])
        
        # Update asset totals if present
        if 'assets' in utxo:
            for asset in utxo['assets']:
                guid = int(asset['guid'])
                amount = Decimal(str(asset['value']))
                if guid in self.total_assets:
                    self.total_assets[guid] += amount
                else:
                    self.total_assets[guid] = amount

    def estimate_current_fee(self, tx_type, num_outputs):
        """Estimate fee for current transaction state."""
        has_asset_data = tx_type != SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION
        return calculate_tx_fee(
            self.node,
            len(self.selected_utxos),
            num_outputs,
            has_op_return=True,
            has_asset_data=has_asset_data
        )

    def select_coins_for_transaction(self, tx_type, sys_amount, asset_amounts=None, fees=None):
        if asset_amounts is None:
            asset_amounts = {}

        asset_amounts = {int(k): v for k, v in asset_amounts.items()}

        initial_fee = fees if fees is not None else Decimal('0.0001')
        total_sys_needed = sys_amount + initial_fee

        self.select_optimal_inputs(total_sys_needed, asset_amounts)

        num_outputs = 1
        if tx_type == SYSCOIN_TX_VERSION_ALLOCATION_SEND:
            num_outputs += len(asset_amounts)
        elif tx_type in [SYSCOIN_TX_VERSION_ALLOCATION_MINT, SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION, SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN]:
            num_outputs += 1

        # Count asset change outputs
        num_asset_change_outputs = sum(
            1 for guid, total in self.total_assets.items()
            if total > asset_amounts.get(guid, Decimal('0'))
        )

        # Account for SYS required for asset change outputs
        DUST_THRESHOLD = Decimal('0.00000546')
        extra_sys_for_asset_changes = DUST_THRESHOLD * num_asset_change_outputs
        total_sys_needed += extra_sys_for_asset_changes

        actual_fee = self.estimate_current_fee(tx_type, num_outputs + num_asset_change_outputs)
        total_sys_needed = sys_amount + actual_fee + (DUST_THRESHOLD * num_asset_change_outputs)

        if self.total_sys < total_sys_needed:
            raise ValueError(f"Not enough SYS: need {total_sys_needed}, have {self.total_sys}")

        raw_sys_change = self.total_sys - total_sys_needed
        sys_change = raw_sys_change if raw_sys_change >= DUST_THRESHOLD else Decimal('0')

        asset_changes = {}
        for guid, total in self.total_assets.items():
            target = asset_amounts.get(guid, Decimal('0'))
            change = total - target
            if change > 0:
                asset_changes[guid] = change

        return True, self.selected_utxos, sys_change, asset_changes

def estimate_asset_commitment_size(asset_amounts=None, tx_type=None, nevm_address=None):
    """
    Estimate the size of the asset commitment in bytes
    
    Args:
        asset_amounts: Dict of {guid: amount} for assets
        tx_type: Transaction type (SYSCOIN_TX_VERSION_*)
        nevm_address: NEVM address for BURN_TO_NEVM
        
    Returns:
        Size of asset commitment in bytes
    """
    if asset_amounts is None:
        asset_amounts = {}
    
    # Convert asset keys to integers if they're strings
    asset_amounts = {int(k) if isinstance(k, str) else k: v for k, v in asset_amounts.items()}
    
    # Base size for CAssetAllocation
    base_size = 1  # 1 byte for asset count
    
    # Special handling for different transaction types
    if tx_type == SYSCOIN_TX_VERSION_SYSCOIN_BURN_TO_ALLOCATION:
        # Creating SYSX from SYS - just one SYSX output
        asset_count = 1
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_SYSCOIN:
        # Burning SYSX to SYS - just one SYSX input
        asset_count = 1
    else:
        # For other types, count the number of assets
        asset_count = len(asset_amounts)
    
    # Size per asset (key + values)
    # Each AssetOut: GUID (4 bytes) + vector size (1 byte) + values
    # Each AssetOutValue: output index (1 byte) + compressed amount (~3-8 bytes)
    per_asset_size = 12  # Average size accounting for variations
    
    # Asset outputs total size
    total_asset_size = asset_count * per_asset_size
    
    # Additional size for specific transaction types
    additional_size = 0
    
    # CMintSyscoin has additional fields for SPV proof
    if tx_type == SYSCOIN_TX_VERSION_ALLOCATION_MINT:
        # txHash (32) + blockHash (32) + txIndex (4) + receiptIndex (4) +
        # txRoot (32) + receiptRoot (32) + parent nodes + paths
        additional_size = 136 + 100  # Fixed fields + estimated size for variable fields
    
    # CBurnSyscoin has NEVM address field
    elif tx_type == SYSCOIN_TX_VERSION_ALLOCATION_BURN_TO_NEVM:
        # NEVM address (typically 20 bytes) + length byte
        additional_size = 21
    
    # Total size
    total_size = base_size + total_asset_size + additional_size
    
    # Add padding for safety (5%)
    return int(total_size * 1.05)

def estimate_tx_size(num_inputs, num_outputs, tx_type=None, asset_amounts=None, nevm_address=None):
    """
    Estimate transaction size in bytes for fee calculation
    
    Args:
        num_inputs: Number of transaction inputs
        num_outputs: Number of transaction outputs
        tx_type: Transaction type (SYSCOIN_TX_VERSION_*)
        asset_amounts: Dict of {guid: amount} for assets
        nevm_address: NEVM address for BURN_TO_NEVM
        
    Returns:
        Estimated transaction size in bytes
    """
    # Base transaction size
    base_size = 10  # version (4) + locktime (4) + input count varint (1) + output count varint (1)
    
    # Input size 
    # prevout (36) + script len (1) + signature script (~107) + sequence (4)
    input_size = num_inputs * 148  
    
    # Regular output size
    # value (8) + script length (1) + pubkey script (~25)
    output_size = num_outputs * 34  
    
    # OP_RETURN output size
    op_return_size = 0
    if tx_type:
        # OP_RETURN itself is very small, but the asset data can be substantial
        # value (8) + script len (1) + OP_RETURN (1) + pushdata + asset data
        asset_data_size = estimate_asset_commitment_size(asset_amounts, tx_type, nevm_address)
        op_return_size = 10 + asset_data_size
    
    # Total estimated size
    total_size = base_size + input_size + output_size + op_return_size
    
    # Add padding for safety (10%)
    return int(total_size * 1.1)

def get_current_fee_rate(node):
    """
    Get the current fee rate from the node
    
    Args:
        node: The node to query
        
    Returns:
        Fee rate in satoshis per kilobyte
    """
    try:
        # Try newer API first
        info = node.getnetworkinfo()
        if 'relayfee' in info:
            # relayfee is in SYS/kB, convert to satoshis/kB
            return Decimal(str(info['relayfee'])) * Decimal('100000000')
    except:
        pass
    
    # Fallback to estimatefee if available
    try:
        # estimatefee returns SYS/kB
        fee_per_kb = node.estimatefee(2)  # Estimate for 2 blocks confirmation
        if fee_per_kb > 0:
            # Convert to satoshis/kB
            return Decimal(str(fee_per_kb)) * Decimal('100000000')
    except:
        pass
    
    # Default fallback
    return Decimal('1000')  # 1000 satoshis/kB (0.00001 SYS/kB)

def calculate_tx_fee(node, num_inputs, num_outputs, has_op_return=True, has_asset_data=True):
    """
    Calculate transaction fee based on input/output counts and current fee rate
    
    Args:
        node: Node to use for getting fee rate
        num_inputs: Number of transaction inputs
        num_outputs: Number of transaction outputs
        has_op_return: Whether transaction has OP_RETURN output
        has_asset_data: Whether OP_RETURN contains asset data
        
    Returns:
        Fee in SYS
    """
    # Validate inputs
    if num_inputs <= 0:
        raise ValueError("Number of inputs must be positive")
    if num_outputs <= 0:
        raise ValueError("Number of outputs must be positive")
    
    # Get current fee rate (satoshis/kB)
    fee_rate = get_current_fee_rate(node)
    
    # Determine transaction type for size estimation
    tx_type = None
    if has_asset_data:
        # Use ALLOCATION_SEND as a default for size estimation
        tx_type = SYSCOIN_TX_VERSION_ALLOCATION_SEND
    
    # Estimate transaction size
    tx_size = estimate_tx_size(
        num_inputs=num_inputs,
        num_outputs=num_outputs,
        tx_type=tx_type,
        asset_amounts={"123456": Decimal('1.0')} if has_asset_data else None
    )
    
    # Calculate fee based on size and rate
    fee_satoshis = Decimal(tx_size) * fee_rate / Decimal(1000)  # fee_rate is in sat/KB
    
    # Convert to SYS with proper rounding
    fee_sys = fee_satoshis / Decimal('100000000')
    
    # Round up to nearest satoshi and ensure minimum fee
    min_fee = Decimal('0.00000010')  # 10 satoshis minimum
    fee = fee_sys.quantize(Decimal('0.00000001'), rounding=ROUND_UP)
    
    return max(fee, min_fee)

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



