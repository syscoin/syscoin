#!/usr/bin/env python3
# Copyright (c) 2015-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test the ZMQ notification interface."""

from test_framework.address import ADDRESS_BCRT1_UNSPENDABLE
from test_framework.test_framework import SyscoinTestFramework
from test_framework.messages import hash256, CNEVMBlock, CNEVMBlockConnect, CNEVMBlockDisconnect, uint256_from_str
from test_framework.util import (
    assert_equal,
    get_rpc_proxy,
    p2p_port,
    force_finish_mnsync,
    assert_raises_rpc_error
)
from io import BytesIO
from decimal import Decimal
from time import sleep
from threading import Thread
import random
class Masternode(object):
    pass

def receive_thread_nevm(test_framework, idx, subscriber):
    while test_framework.running:
        try:
            data = subscriber.receive()
            if data[0] == b"nevmcomms":
                subscriber.send([b"nevmcomms", b"ack"])
            elif data[0] == b"nevmblock":
                hashStr = hash256(str(random.randint(-0x80000000, 0x7fffffff)).encode())
                hashTopic = uint256_from_str(hashStr)
                nevmBlock = CNEVMBlock()
                nevmBlock.nBlockHash = hashTopic
                nevmBlock.nTxRoot = hashTopic
                nevmBlock.nReceiptRoot = hashTopic
                nevmBlock.vchNEVMBlockData = b"nevmblock"
                subscriber.send([b"nevmblock", nevmBlock.serialize()])
            elif data[0] == b"nevmconnect":
                evmBlockConnect = CNEVMBlockConnect()
                evmBlockConnect.deserialize(BytesIO(data[1]))
                resBlock = subscriber.addBlock(evmBlockConnect)
                res = b"connected" if resBlock else b"not connected"
                while subscriber.artificialDelay and test_framework.running:
                    sleep(0.1)
                subscriber.send([b"nevmconnect", res])
            elif data[0] == b"nevmdisconnect":
                evmBlockDisconnect = CNEVMBlockDisconnect()
                evmBlockDisconnect.deserialize(BytesIO(data[1]))
                resBlock = subscriber.deleteBlock(evmBlockDisconnect)
                res = b"disconnected" if resBlock else b"not disconnected"
                subscriber.send([b"nevmdisconnect", res])
            else:
                test_framework.log.info("Unknown topic in REQ {}".format(data))
        except zmq.ContextTerminated:
            sleep(1)
            break
        except zmq.ZMQError:
            test_framework.log.warning('zmq error, socket closed unexpectedly.')
            sleep(1)
            break

def thread_generate(test_framework, node):
    test_framework.log.info('thread_generate start')
    test_framework.generatetoaddress(node, 1, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=test_framework.no_op)
    test_framework.log.info('thread_generate done')

try:
    import zmq
except ImportError:
    pass

class ZMQPublisher:
    def __init__(self,log, socket):
        self.socket = socket
        self.log = log
        self.sysToNEVMBlockMapping = {}
        self.NEVMToSysBlockMapping = {}
        self.sysToBTCPrevHashMapping = {}
        self.mnNEVMAddressMapping = {}
        self.artificialDelay = False

    # Send message to subscriber
    def _send_to_publisher_and_check(self, msg_parts):
        self.socket.send_multipart(msg_parts)

    def receive(self):
        return self.socket.recv_multipart()

    def send(self, msg_parts):
        return self._send_to_publisher_and_check(msg_parts)

    def close(self):
        self.socket.close()

    def _process_nevm_address_diff(self, addedMNNEVM, updatedMNNEVM, removedMNNEVM):
        """
        Processes NEVM address changes by adding new addresses, updating existing ones, and removing deleted addresses.
        """
        for entry in addedMNNEVM:
            addressKey = '0x' + entry.address.hex()
            self.mnNEVMAddressMapping[addressKey] = entry.collateralHeight
        
        # Handle updated NEVM addresses
        for entry in updatedMNNEVM:
            oldAddressKey = '0x' + entry.oldAddress.hex()
            newAddressKey = '0x' + entry.newAddress.hex()
            # Update to the new address before removing the old one
            if oldAddressKey in self.mnNEVMAddressMapping:
                self.mnNEVMAddressMapping[newAddressKey] = self.mnNEVMAddressMapping.pop(oldAddressKey)

        # Handle removed NEVM addresses
        for nevmAddress in removedMNNEVM:
            addressKey = '0x' + nevmAddress.address.hex()
            if addressKey in self.mnNEVMAddressMapping:
                del self.mnNEVMAddressMapping[addressKey]

                
    def addBlock(self, evmBlockConnect):
        # Process NEVM address diff
        self._process_nevm_address_diff(
            evmBlockConnect.diff.addedMNNEVM,
            evmBlockConnect.diff.updatedMNNEVM,
            evmBlockConnect.diff.removedMNNEVM
        )
        if evmBlockConnect.sysblockhash == 0:
            return True
        if (evmBlockConnect.sysblockhash in self.sysToNEVMBlockMapping or 
            evmBlockConnect.evmBlock.nBlockHash in self.NEVMToSysBlockMapping):
            return False
        
        self.sysToNEVMBlockMapping[evmBlockConnect.sysblockhash] = evmBlockConnect
        self.NEVMToSysBlockMapping[evmBlockConnect.evmBlock.nBlockHash] = evmBlockConnect.sysblockhash
        self.sysToBTCPrevHashMapping[evmBlockConnect.sysblockhash] = evmBlockConnect.btcprevhash
        

        
        return True

    def deleteBlock(self, evmBlockDisconnect):
        # Process NEVM address diff (no need to reverse anything)
        self._process_nevm_address_diff(
            evmBlockDisconnect.diff.addedMNNEVM,
            evmBlockDisconnect.diff.updatedMNNEVM,
            evmBlockDisconnect.diff.removedMNNEVM
        )
        nevmConnect = self.sysToNEVMBlockMapping.get(evmBlockDisconnect.sysblockhash)
        if nevmConnect is None:
            return False
        
        sysMappingHash = self.NEVMToSysBlockMapping.get(nevmConnect.evmBlock.nBlockHash)
        if sysMappingHash is None or sysMappingHash != nevmConnect.sysblockhash:
            return False
        

        
        # Remove the block from the mapping
        del self.sysToNEVMBlockMapping[evmBlockDisconnect.sysblockhash]
        del self.NEVMToSysBlockMapping[nevmConnect.evmBlock.nBlockHash]
        if evmBlockDisconnect.sysblockhash in self.sysToBTCPrevHashMapping:
            del self.sysToBTCPrevHashMapping[evmBlockDisconnect.sysblockhash]
        
        return True

    def getLastSYSBlock(self):
        if not self.NEVMToSysBlockMapping:
            return 0
        return list(self.NEVMToSysBlockMapping.values())[-1]

    def getLastNEVMBlock(self):
        if not self.sysToNEVMBlockMapping:
            return None
        return self.sysToNEVMBlockMapping[self.getLastSYSBlock()]

    def getLastBTCPrevHash(self):
        last = self.getLastSYSBlock()
        if last == 0:
            return 0
        return self.sysToBTCPrevHashMapping.get(last, 0)

    def clearMappings(self):
        self.sysToNEVMBlockMapping = {}
        self.NEVMToSysBlockMapping = {}
        self.sysToBTCPrevHashMapping = {}
        self.mnNEVMAddressMapping = {}
        
    def assertMNList(self, expected_mn_mapping):
        print(f"Mapping: {self.mnNEVMAddressMapping}")
        print(f"Expected: {expected_mn_mapping}")
        assert self.mnNEVMAddressMapping == expected_mn_mapping, "MN mapping did not match expected state"

class ZMQTest(SyscoinTestFramework):

    def add_options(self, parser):
        # This test is descriptor-only; do not expose legacy wallet mode.
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    def set_test_params(self):
        self.num_nodes = 2
        self.extra_args = [
            ["-whitelist=noban@127.0.0.1", "-nevmstartheight=205", "-mncollateral=100", "-dip3params=204:204"],
            ["-whitelist=noban@127.0.0.1", "-nevmstartheight=205", "-mncollateral=100", "-dip3params=204:204"]
        ]
        
    def skip_test_if_missing_module(self):
        self.skip_if_no_py3_zmq()
        self.skip_if_no_syscoind_zmq()
        if self.options.descriptors is not True:
            self.log.info("ZMQ NEVM test forces descriptor wallets")
        self.options.descriptors = True
        self.default_wallet_name = "default_wallet"
        self.skip_if_no_wallet()

    def run_test(self):
        try:
            import zmq
        except ImportError:
            pass
        self.running = True
        self.ctx = zmq.Context()
        self.ctxpub = zmq.Context()
        self.threads = []
        try:
            self.configure_pq_migration_anchor()
            address = 'tcp://127.0.0.1:29458'
            address1 = 'tcp://127.0.0.1:29459'

            self.log.info("Setup subscribers...")
            nevmsub = self.setup_zmq_test(address, 0)
            nevmsub1 = self.setup_zmq_test(address1, 1)
            self.connect_nodes(0, 1)
            self.sync_blocks()

            num_blocks = 10
            self.log.info("Generate %(n)d blocks (and %(n)d coinbase txes)" % {"n": num_blocks})
            t1 = Thread(target=receive_thread_nevm, args=(self, 0, nevmsub,))
            t2 = Thread(target=receive_thread_nevm, args=(self, 1, nevmsub1,))
            t1.start()
            t2.start()
            self.threads.extend([t1, t2])
            for i in range(len(self.nodes)):
                force_finish_mnsync(self.nodes[i])
            self.generatetoaddress(self.nodes[0], num_blocks, ADDRESS_BCRT1_UNSPENDABLE)
            self.sync_blocks()
            self.mn_count = 0
            self.test_basic(nevmsub, nevmsub1)
            self.test_nevm_mapping(nevmsub)
            self.test_nevm_edge_cases(nevmsub)
        finally:
            self.running = False
            self.log.debug("Destroying ZMQ context")
            self.ctx.destroy(linger=None)
            self.ctxpub.destroy(linger=None)
            for t in self.threads:
                t.join()

    def configure_pq_migration_anchor(self):
        # SYSCOIN: Pin migration immediately before NEVM activation so the
        # subscribers observe block 205 and can test the 206 -> 205 rollback.
        dip3_height = 204
        current_height = self.nodes[0].getblockcount()
        assert current_height <= dip3_height
        if current_height < dip3_height:
            self.generatetoaddress(
                self.nodes[0], dip3_height - current_height,
                self.nodes[0].getnewaddress())
            self.sync_blocks()
        anchor = self.nodes[0].protx_migration_info()
        assert_equal(anchor['height'], dip3_height)
        registration_cutoff_blocks = 288
        # SYSCOIN: roster membership is sampled only after root registration closes.
        roster_snapshot_lag = 288
        btcc_candidate_origin = 1_000_000
        assert registration_cutoff_blocks >= roster_snapshot_lag
        pq_args = [
            '-pqlegacyanchorheight=%d' % anchor['height'],
            '-pqlegacyanchorblockhash=%s' % anchor['blockHash'],
            '-pqlegacydmnstatehash=%s' % anchor['dmnStateHash'],
            '-pqlegacypqregistrystatehash=%s' % anchor['pqRegistryStateHash'],
            '-pqpreparationheight=%d' % dip3_height,
            '-pqchainlockepochorigin=1440',
            '-pqregistrationcutoffblocks=%d' % registration_cutoff_blocks,
            '-pqrostersnapshotlag=%d' % roster_snapshot_lag,
            '-pqfuturehorizonepochs=8',
            '-pqbtcccandidateorigin=%d' % btcc_candidate_origin,
            # SYSCOIN: First activation uses a distinct pre-carrier empty
            # receipt-state assumption record at the migration boundary.
            '-pqbtccreceiptanchorheight=%d' % anchor['height'],
            '-pqbtccreceiptanchorblockhash=%s' % anchor['blockHash'],
            '-pqbtccreceiptanchorcursorheight=-1',
            '-pqbtccreceiptanchorcursorsyshash=%s' % ('0' * 64),
            '-pqbtccreceiptanchorcursorbtchash=%s' % ('0' * 64),
            '-pqbtccreceiptanchorstatehash=%s' % ('0' * 64),
        ]
        for args in self.extra_args:
            args.extend(pq_args)
        self.stop_nodes()
        for index in range(self.num_nodes):
            self.nodes[index].extra_args = list(self.extra_args[index])
        # SYSCOIN: This test starts from the shared cached chain. Rebuild the
        # UTXO, deterministic-MN, and PQ-registry state while retaining its
        # validated block index so the exact migration anchor can be replayed.
        self.start_node(0, extra_args=self.extra_args[0] + ['-reindex-chainstate'])
        self.start_node(1, extra_args=self.extra_args[1] + ['-reindex-chainstate'])
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(self.nodes[0].protx_migration_info(), anchor)
        assert_equal(self.nodes[1].protx_migration_info(), anchor)

    def setup_zmq_test(self, address, idx, *, recv_timeout=60):
        socket = self.ctx.socket(zmq.REP)
        subscriber = ZMQPublisher(self.log, socket)
        self.extra_args[idx] += ["-zmqpubnevm=%s" % address]

        self.restart_node(idx, self.extra_args[idx])

        subscriber.socket.bind(address)
        subscriber.socket.setsockopt(zmq.RCVTIMEO, recv_timeout * 1000)
        return subscriber

    def test_basic(self, nevmsub, nevmsub1):
        bestblockhash = self.nodes[0].getbestblockhash()
        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastBTCPrevHash(), nevmsub.getLastBTCPrevHash())

        prevblockhash = self.nodes[0].getblockhash(205)
        blockhash = self.nodes[0].getblockhash(206)
        self.nodes[0].invalidateblock(blockhash)
        self.nodes[1].invalidateblock(blockhash)
        self.sync_blocks()

        assert_equal(int(prevblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastBTCPrevHash(), nevmsub.getLastBTCPrevHash())

        self.nodes[0].reconsiderblock(blockhash)
        self.nodes[1].reconsiderblock(blockhash)
        self.sync_blocks()

        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastBTCPrevHash(), nevmsub.getLastBTCPrevHash())

        self.log.info('Restarting node 0')
        self.restart_node(0, self.extra_args[0])
        self.sync_blocks()

        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastBTCPrevHash(), nevmsub.getLastBTCPrevHash())

        self.log.info('Restarting node 1')
        self.restart_node(1, self.extra_args[1])
        self.connect_nodes(0, 1)
        self.sync_blocks()

        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastBTCPrevHash(), nevmsub.getLastBTCPrevHash())

        self.log.info('Reindexing chainstate on node 0')
        # SYSCOIN: Replaying the chainstate is the operation under test here:
        # it reconstructs NEVM notifications without discarding the cached,
        # already-validated block index that identifies the migration branch.
        self.extra_args[0] += ["-reindex-chainstate"]
        nevmsub.clearMappings()
        self.restart_node(0, self.extra_args[0])
        self.connect_nodes(0, 1)
        self.sync_blocks()

        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastBTCPrevHash(), nevmsub.getLastBTCPrevHash())

        self.log.info('Reindexing chainstate on node 1')
        self.extra_args[1] += ["-reindex-chainstate"]
        nevmsub1.clearMappings()
        self.restart_node(1, self.extra_args[1])
        self.connect_nodes(0, 1)
        self.sync_blocks()

        assert_equal(int(bestblockhash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[1].getbestblockhash(), bestblockhash)
        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(nevmsub1.getLastBTCPrevHash(), nevmsub.getLastBTCPrevHash())

        common_height = self.nodes[0].getblockcount()
        assert_equal(self.nodes[1].getblockcount(), common_height)
        self.disconnect_nodes(0, 1)
        self.log.info("Mine 4 blocks on Node 0")
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        self.generatetoaddress(self.nodes[0], 4, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), common_height)
        assert_equal(self.nodes[0].getblockcount(), common_height + 4)
        besthash_n0 = self.nodes[0].getbestblockhash()

        self.log.info("Mine competing 6 blocks on Node 1")
        self.generatetoaddress(self.nodes[1], 6, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        assert_equal(self.nodes[1].getblockcount(), common_height + 6)

        self.log.info("Connect nodes to force a reorg")
        self.connect_nodes(0, 1)
        self.sync_blocks()
        assert_equal(self.nodes[0].getblockcount(), common_height + 6)
        badhash = self.nodes[1].getblockhash(common_height + 2)

        self.log.info("Invalidate block 2 on node 0 and verify we reorg to node 0's original chain")
        self.nodes[0].invalidateblock(badhash)
        assert_equal(self.nodes[0].getblockcount(), common_height + 4)
        assert_equal(self.nodes[0].getbestblockhash(), besthash_n0)
        self.nodes[0].reconsiderblock(badhash)
        self.sync_blocks()

        self.log.info("Artificially delaying node0")
        nevmsub.artificialDelay = True
        self.log.info("Generating on node0 in separate thread")
        t3 = Thread(target=thread_generate, args=(self, self.nodes[0],))
        t3.start()
        self.threads.append(t3)

        self.log.info("Creating re-org and letting node1 become longest chain, node0 should re-org to node0")
        self.generatetoaddress(self.nodes[1], 10, ADDRESS_BCRT1_UNSPENDABLE, sync_fun=self.no_op)
        besthash = self.nodes[1].getbestblockhash()
        nevmsub.artificialDelay = False
        sleep(1)
        self.sync_blocks()

        assert_equal(nevmsub1.getLastSYSBlock(), nevmsub.getLastSYSBlock())
        assert_equal(int(besthash, 16), nevmsub.getLastSYSBlock())
        assert_equal(self.nodes[0].getbestblockhash(), self.nodes[1].getbestblockhash())
        assert_equal(nevmsub1.getLastBTCPrevHash(), nevmsub.getLastBTCPrevHash())
    
    def test_nevm_mapping(self, nevmsub):
        nevmsub.clearMappings()
        self.mns = []
        # Test case 1: Create MN with NEVM address (should add)
        self.log.info("Creating MN with NEVM address")
        mn1_nevm_address = "0x000000000000000000000000000000000000bEEF"
        mn = self.create_mn_with_nevm(1, "nevm-mn", mn1_nevm_address)
        self.mns.append(mn)
        self.sync_blocks()
        expected_mapping = {mn1_nevm_address.lower(): self.mns[0].collateral_height}
        nevmsub.assertMNList(expected_mapping)
    
        # Test case 2: Create MN without NEVM address
        self.log.info("Creating MN without NEVM address")
        mn = self.create_mn_with_nevm(2, "non-nevm-mn")
        self.mns.append(mn)
        self.sync_blocks()
        nevmsub.assertMNList(expected_mapping)  # No change in NEVM mapping

        # Test case 3: Update MN to set NEVM address (should add)
        self.log.info("Updating MN to set NEVM address")
        mn2_nevm_address = "0x00000000000000000000000000000000dEaDbEEF"
        self.update_mn_set_nevm(self.mns[1], mn2_nevm_address)
        self.sync_blocks()
        self.mns[1].last_update_height = self.nodes[0].getblockcount()
        expected_mapping[mn2_nevm_address.lower()] = self.mns[1].collateral_height
        nevmsub.assertMNList(expected_mapping)

        # Test case 4: Update MN to change NEVM address (should update)
        self.log.info("Updating MN to change NEVM address")
        new_mn1_nevm_address = "0x000000000000000000000000000000000000dEaD"
        self.update_mn_set_nevm(self.mns[0], new_mn1_nevm_address)
        self.sync_blocks()
        self.mns[0].last_update_height = self.nodes[0].getblockcount()
        del expected_mapping[mn1_nevm_address.lower()]
        expected_mapping[new_mn1_nevm_address.lower()] = self.mns[0].collateral_height
        nevmsub.assertMNList(expected_mapping)

        # Test case 5: Update MN to remove NEVM address (should remove)
        self.log.info("Updating MN to remove NEVM address")
        self.update_mn_set_nevm(self.mns[1], '')
        self.sync_blocks()
        self.mns[1].last_update_height = self.nodes[0].getblockcount()
        del expected_mapping[mn2_nevm_address.lower()]
        nevmsub.assertMNList(expected_mapping)

        # Test case 6: Remove MN (should remove NEVM address) via spending collateral
        self.log.info("Removing MN by spending collateral")
        self.remove_mn(self.mns[0])
        self.sync_blocks()
        self.mns[1].removal_height = self.nodes[0].getblockcount()
        del expected_mapping[new_mn1_nevm_address.lower()]
        nevmsub.assertMNList(expected_mapping)

        # The MN should release the address from global storage so another MN can take it
        self.log.info("Updating MN to NEVM address to that of previous removed MN")
        self.update_mn_set_nevm(self.mns[1], new_mn1_nevm_address)
        self.sync_blocks()
        self.mns[1].last_update_height = self.nodes[0].getblockcount()
        expected_mapping[new_mn1_nevm_address.lower()] = self.mns[1].collateral_height
        nevmsub.assertMNList(expected_mapping)
        
        # Test case 7: Reorg that undoes an MN creation (should remove NEVM address)
        self.log.info("Reorg to undo MN creation")
        invalidblock = self.reorg(self.mns[0].collateral_height)
        nevmsub.assertMNList({})
        # sync back to tip
        self.nodes[0].reconsiderblock(invalidblock)
        self.sync_blocks()
        nevmsub.assertMNList(expected_mapping)
        
        # Test case 8: Reorg that undoes an MN update (should revert to previous NEVM address)
        self.log.info("Reorg to undo MN update")
        invalidblock = self.reorg(self.mns[0].last_update_height)
        nevmsub.assertMNList({mn1_nevm_address.lower(): self.mns[0].collateral_height, mn2_nevm_address.lower(): self.mns[1].collateral_height})
        # sync back to tip
        self.nodes[0].reconsiderblock(invalidblock)
        self.sync_blocks()
        nevmsub.assertMNList(expected_mapping)

        # Test case 9: Reorg that undoes an MN removal (should re-add NEVM address)
        self.log.info("Reorg to undo MN removal")
        self.reorg(self.mns[1].removal_height)
        nevmsub.assertMNList({new_mn1_nevm_address.lower(): self.mns[0].collateral_height})
        # sync back to tip
        self.nodes[0].reconsiderblock(invalidblock)
        self.sync_blocks()
        nevmsub.assertMNList(expected_mapping)
        self.log.info('NEVM address mapping tests done')

    def test_nevm_edge_cases(self, nevmsub):
        """
        Additional tests for:
         - Multiple NEVM updates in one block (only the final value should be registered)
         - Reorg (undo) scenarios that revert NEVM changes
         - Mempool conflict check for duplicate NEVM addresses
        """
        self.log.info("Starting NEVM edge case tests")
        # Clear any previous state.
        nevmsub.clearMappings()
        start_height = self.nodes[0].getblockcount() + 1
        self.mns = []
    
        # Create an MN with an initial NEVM address.
        self.log.info("Edge Case 1: Create MN with NEVM address")
        mn1_nevm_address = "0x000000000000000000000000000000000000bEEF"
        mn = self.create_mn_with_nevm(3, "edge-nevm-mn", mn1_nevm_address)
        self.mns.append(mn)
        self.sync_blocks()
        expected_mapping = {mn1_nevm_address.lower(): self.mns[0].collateral_height}
        nevmsub.assertMNList(expected_mapping)
    
        # Update the same MN with two successive updates.
        self.log.info("Edge Case 2: Multiple updates in succession")
        self.update_mn_set_nevm(self.mns[0], "0x1111111111111111111111111111111111111111")
        # Ensure global uniqueness updates - mn1_nevm_address should be available again after previous update
        self.update_mn_set_nevm(self.mns[0], mn1_nevm_address)
        self.sync_blocks()
        # Expect that the final state is as originally set.
        nevmsub.assertMNList(expected_mapping)
    
        # Force a reorg that undoes the update.
        self.log.info("Edge Case 3: Reorg to undo MN update")
        block_to_invalidate = self.reorg(start_height)
        # After reorg, the MN should be in the state prior to the update.
        expected_mapping_reorg = {}  # If this MN wasn't confirmed in the old chain, mapping is empty.
        nevmsub.assertMNList(expected_mapping_reorg)
        self.nodes[0].reconsiderblock(block_to_invalidate)
        self.sync_blocks()
        # Mapping should be restored.
        nevmsub.assertMNList(expected_mapping)
    
        # Test mempool conflict: attempt to update another MN with a duplicate NEVM address.
        self.log.info("Edge Case 4: Mempool duplicate NEVM conflict")
        mn = self.create_mn_with_nevm(4, "edge-non-nevm-mn")
        self.mns.append(mn)
        self.sync_blocks()
        # Update mn2 to set its NEVM address.
        mn2_nevm_address = "0x1111111111111111111111111111111111111111"
        self.update_mn_set_nevm(self.mns[1], mn2_nevm_address)
        self.sync_blocks()
        expected_mapping[mn2_nevm_address.lower()] = self.mns[1].collateral_height
        nevmsub.assertMNList(expected_mapping)
        # Now attempt to update mn2 (or a different MN) with the same NEVM address as mn1.
        # SYSCOIN: Use a throwaway confirmed fee input because the expected
        # rejection may leave its selected input unavailable to later checks.
        duplicate_fee_address = self.nodes[0].getnewaddress()
        self.nodes[0].sendtoaddress(duplicate_fee_address, 1)
        self.generate(self.nodes[0], 1)
        assert_raises_rpc_error(-4, 'bad-protx-dup-nevm-address', 
                                self.nodes[0].protx_update_service,  
                                self.mns[1].protx_hash, 
                                '127.0.0.2:%d' % self.mns[1].p2p_port,
                                self.mns[1].operatorKey,
                                mn1_nevm_address,
                                "",
                                duplicate_fee_address)
        # not 20 bytes
        assert_raises_rpc_error(-5, 'Invalid NEVM address (must be 20 bytes / 40 hex chars)', 
                        self.nodes[0].protx_update_service,  
                        self.mns[0].protx_hash, 
                        '127.0.0.2:%d' % self.mns[0].p2p_port,
                        self.mns[0].operatorKey,
                        "0x11111111111111111111111111111111111111",
                        "",
                        self.mns[1].fundsAddr)
        # not hex
        assert_raises_rpc_error(-5, 'Invalid NEVM address (must be 20 bytes / 40 hex chars)', 
                        self.nodes[0].protx_update_service,  
                        self.mns[0].protx_hash, 
                        '127.0.0.2:%d' % self.mns[0].p2p_port,
                        self.mns[0].operatorKey,
                        "0x1111111111111111111111111111111111111L",
                        "",
                        self.mns[1].fundsAddr)
        self.log.info("NEVM edge case tests passed successfully.")

    def prepare_mn(self, node, idx, alias):
        mn = Masternode()
        mn.idx = idx
        mn.alias = alias
        mn.is_protx = True
        mn.p2p_port = p2p_port(mn.idx)

        operator_keys = node.protx_generate_operator_keypair()
        mn.fundsAddr = node.getnewaddress()
        mn.ownerAddr = node.getnewaddress()
        mn.votingAddr = mn.ownerAddr
        mn.operatorKey = operator_keys['operatorKey']
        mn.c11Seed = operator_keys['c11Seed']
        return mn

    def create_mn_with_nevm(self, index, alias, nevm_address = None):
        """Create a masternode with the specified NEVM address"""
        mn = self.prepare_mn(self.nodes[0], index, alias)
        self.nodes[0].sendtoaddress(mn.fundsAddr, 100.001)
        mn.collateral_address = self.nodes[0].getnewaddress()
        mn.rewards_address = self.nodes[0].getnewaddress()
        self.nodes[0].sendtoaddress(mn.rewards_address, 0.001)

        mn.protx_hash = self.nodes[0].protx_register_fund( mn.collateral_address, '127.0.0.1:%d' % mn.p2p_port, mn.ownerAddr, "", mn.votingAddr, 0, mn.rewards_address, mn.fundsAddr)
        mn.collateral_txid = mn.protx_hash
        mn.collateral_vout = -1

        rawtx = self.nodes[0].getrawtransaction(mn.collateral_txid, 1)
        for txout in rawtx['vout']:
            if txout['value'] == Decimal(100):
                mn.collateral_vout = txout['n']
                break
        assert mn.collateral_vout != -1
        mn.collateral_height = self.nodes[0].getblockcount() + 1
        self.mn_count = self.mn_count + 1
        self.generate(self.nodes[0], 1)
        # SYSCOIN: Building and signing the fixed C11 root can exceed the
        # ordinary RPC timeout on reference SLH-DSA builds. Scope the larger
        # budget to this cryptographic setup call only.
        operator_registration_rpc = get_rpc_proxy(
            self.nodes[0].url,
            self.nodes[0].index,
            timeout=600,
            coveragedir=self.nodes[0].coverage_dir,
        )
        operator_registration_rpc.protx_register_operator_key(
            mn.protx_hash, mn.operatorKey, mn.c11Seed, mn.fundsAddr)
        self.generate(self.nodes[0], 1)
        self.nodes[0].protx_update_service(
            mn.protx_hash, '127.0.0.1:%d' % mn.p2p_port,
            mn.operatorKey, "", "", mn.fundsAddr)
        self.generate(self.nodes[0], 1)
        if nevm_address is not None:
            # SYSCOIN: PQ service authorization becomes usable only after the
            # operator-root transaction is mined. On regtest that same block
            # confirms the new MN, so the legacy intermediate state (active
            # operator but unconfirmed MN) is intentionally unreachable.
            self.generate(self.nodes[0], (self.mn_count+1)*2 + 1)
            self.update_mn_set_nevm(mn, nevm_address)
        else:
            self.generate(self.nodes[0], 1)
            self.generate(self.nodes[0], (self.mn_count+1)*2 + 1)
        return mn

    def update_mn_set_nevm(self, mn, nevm_address):
        """Update an MN to set an NEVM address"""
        # SYSCOIN: Each batch ends with an intentional mempool rejection,
        # which can retain the selected fee input. Isolate that side effect
        # with a fresh confirmed input instead of draining the MN setup fund.
        update_fee_address = self.nodes[0].getnewaddress()
        self.nodes[0].sendtoaddress(update_fee_address, 1)
        self.generate(self.nodes[0], 1)
        self.nodes[0].protx_update_service( mn.protx_hash, '127.0.0.2:%d' % p2p_port(7), mn.operatorKey, "0x1111111111111111111111111111111111111110", "", update_fee_address)
        self.nodes[0].protx_update_service( mn.protx_hash, '127.0.0.2:%d' % p2p_port(8), mn.operatorKey, "0x1111111111111111111111111111111111111112", "", update_fee_address)
        self.nodes[0].protx_update_service( mn.protx_hash, '127.0.0.2:%d' % p2p_port(9), mn.operatorKey, "0x1111111111111111111111111111111111111113", "", update_fee_address)
        self.nodes[0].protx_update_service( mn.protx_hash, '127.0.0.2:%d' % p2p_port(10), mn.operatorKey,"0x1111111111111111111111111111111111111114", "", update_fee_address)
        self.nodes[0].protx_update_service( mn.protx_hash, '127.0.0.2:%d' % p2p_port(11), mn.operatorKey, "", "", update_fee_address)
        self.nodes[0].protx_update_service( mn.protx_hash, '127.0.0.2:%d' % mn.p2p_port, mn.operatorKey, nevm_address,  "", update_fee_address)

        # dis-allow multiple in mempool from same MN
        if nevm_address:
            assert_raises_rpc_error(-4, 'protx-dup', self.nodes[0].protx_update_service,  mn.protx_hash, '127.0.0.2:%d' % mn.p2p_port, mn.operatorKey, nevm_address, "", update_fee_address)
        self.generate(self.nodes[0], 1)
        # Verify NEVM address was set correctly
        mn_info = self.nodes[0].masternode_list("nevmaddress", f"{mn.collateral_txid}-{mn.collateral_vout}")
        mn_outpoint = f"{mn.collateral_txid}-{mn.collateral_vout}"
        assert mn_outpoint in mn_info, f"Masternode {mn_outpoint} not found in masternodelist"

        # Handle the empty address case safely
        info_parts = mn_info[mn_outpoint].split()
        actual_nevm_address = info_parts[-1] if info_parts else ''

        assert actual_nevm_address.lower() == nevm_address.lower(), (
            f"NEVM address mismatch: expected '{nevm_address}', got '{actual_nevm_address}'"
        )

    def spend_input(self, txid, vout, amount):
        address = self.nodes[0].getnewaddress()

        txins = [
            {'txid': txid, 'vout': vout}
        ]
        targets = {address: amount}

        rawtx = self.nodes[0].createrawtransaction(txins, targets)
        rawtx = self.nodes[0].fundrawtransaction(rawtx)['hex']
        rawtx = self.nodes[0].signrawtransactionwithwallet(rawtx)['hex']
        self.nodes[0].sendrawtransaction(rawtx)
        return self.generate(self.nodes[0], 1)
    
    def remove_mn(self, mn):
        """Spend collateral to remove MN (which should also remove its NEVM address)"""
        return self.spend_input(mn.collateral_txid, mn.collateral_vout, 100)

    def reorg(self, height):
        """Perform a reorg"""
        block_hash = self.nodes[0].getblockhash(height)
        self.nodes[0].invalidateblock(block_hash)
        assert_equal(self.nodes[0].getblockcount(), height - 1)
        return block_hash

if __name__ == '__main__':
    ZMQTest().main()
