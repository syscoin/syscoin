#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import secrets
import random
import time
from threading import Event, Thread
from io import BytesIO
from test_framework.test_framework import DashTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, force_finish_mnsync
from test_framework.messages import (
    NEVM_DATA_EXPIRE_TIME,
    MAX_DATA_BLOBS,
    MAX_NEVM_DATA_BLOB,
    CNEVMBlock,
    CNEVMBlockConnect,
    hash256,
    uint256_from_str,
)

class NEVMDataTest(DashTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.set_dash_test_params(5, 4, [["-disablewallet=0","-walletrejectlongchains=0"]] * 5, fast_dip3_enforcement=True)
        # Activate NEVM commitment path in this test's height range.
        for i in range(self.num_nodes):
            self.extra_args[i].append("-nevmstartheight=1")

    def skip_test_if_missing_module(self):
        self.skip_if_no_py3_zmq()
        self.skip_if_no_syscoind_zmq()
        self.skip_if_no_wallet()

    def assert_no_pq_finality(self, nodes=None):
        # SYSCOIN: this five-node data fixture has only four registered
        # operators. The production PQ profile is fixed at 400 members, so it
        # must fail closed instead of manufacturing regtest ChainLocks.
        for node in nodes or self.nodes:
            assert_raises_rpc_error(
                -32603, "Unable to find any ChainLock",
                node.getbestchainlock)
            assert_raises_rpc_error(
                -32603, "Unable to find any chainlock",
                node.getchainlocks)

    def sync_without_finality(self, nodes=None, timeout=180):
        nodes = nodes or self.nodes
        self.wait_until(lambda: self.sync_blocks_helper(nodes), timeout=timeout)
        self.assert_no_pq_finality(nodes)

    def assert_blob_is_not_chainlocked(self, versionhash, nodes=None):
        # SYSCOIN: NEVM data remains queryable without falsely reporting PQ
        # finality when the fixed production roster cannot be formed.
        nodes = nodes or self.nodes
        self.assert_no_pq_finality(nodes)
        for node in nodes:
            assert_equal(
                node.getnevmblobdata(versionhash).get('chainlock', False),
                False)

    def nevm_data_max_size_blob(self):
        print('Testing for max size of a blob (2MB)')
        blobDataMax = secrets.token_hex(MAX_NEVM_DATA_BLOB)
        print('Creating large blob (2MB)...')
        vh = self.nodes[0].syscoincreatenevmblob(blobDataMax)['versionhash']
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes))
        print('Generating block...')
        self.generate_helper(self.nodes[0], 5)
        self.sync_without_finality()
        print('Testing nodes to see if blob exists...')
        assert_equal(self.nodes[0].getnevmblobdata(vh, True)['data'], blobDataMax)
        assert_equal(self.nodes[1].getnevmblobdata(vh, True)['data'], blobDataMax)
        assert_equal(self.nodes[2].getnevmblobdata(vh, True)['data'], blobDataMax)
        assert_equal(self.nodes[3].getnevmblobdata(vh, True)['data'], blobDataMax)
        assert_equal(self.nodes[4].getnevmblobdata(vh, True)['data'], blobDataMax)
        vh = secrets.token_hex(32)
        print('Trying 2MB + 1 to ensure it cannot create blob...')
        blobDataMaxPlus = secrets.token_hex(MAX_NEVM_DATA_BLOB + 1)
        txBad = self.nodes[0].syscoincreatenevmblob(blobDataMaxPlus)['txid']
        assert_raises_rpc_error(-5, "No such mempool transaction", self.nodes[1].getrawtransaction, txid=txBad)
        print('Making 2MB * MAX_DATA_BLOBS+1...')
        self.blobVHs = []
        for i in range(0, 33):
            blobDataMax = secrets.token_hex(MAX_NEVM_DATA_BLOB)
            vh = self.nodes[0].syscoincreatenevmblob(blobDataMax)['versionhash']
            self.blobVHs.append(vh)
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes))
        print('Generating block...')
        tip = self.generate(self.nodes[0], 1)[-1]
        rpc_details = self.nodes[0].getblock(tip, True)
        print('Ensure fees will be properly calculated due to the block size being correctly calculated based on PoDA policy (100x factor of blob data)...')
        assert rpc_details["size"] > 670000 and rpc_details["size"]  < 680000
        foundCount = 0
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes))
        # get the tip block's MTP
        mtp = self.nodes[0].getblockheader(tip)["mediantime"]
        foundCount = 0
        print('Testing nodes to see if MAX_DATA_BLOBS blobs exist at 2MB each in the tip...')
        for i, blobVH in enumerate(self.blobVHs):
            try:
                blob = self.nodes[1].getnevmblobdata(blobVH)
                if blob['mtp'] == mtp:
                    foundCount += 1
            except Exception:
                pass

        assert_equal(foundCount, MAX_DATA_BLOBS)
        print('Generating next block...')
        tip = self.generate(self.nodes[0], 1)[-1]
        mtp = self.nodes[0].getblockheader(tip)["mediantime"]
        print('Testing nodes to see if MAX_DATA_BLOBS+1 blobs exist after the next block...')
        for i, blobVH in enumerate(self.blobVHs):
            try:
                blob = self.nodes[1].getnevmblobdata(blobVH)
                if blob['mtp'] == mtp:
                    foundCount += 1
            except Exception:
                pass

        assert_equal(foundCount, MAX_DATA_BLOBS+1)
        self.generate(self.nodes[0], 3)
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes))

    def nevm_data_block_max_blobs(self):
        print('Testing for max number of blobs in a block (32)')
        self.blobVHs = []
        print('Populate 2 * MAX_DATA_BLOBS blobs in mempool (64)')
        for i in range(0, MAX_DATA_BLOBS*2):
            vh = self.nodes[0].syscoincreatenevmblob(secrets.token_hex(55))['versionhash']
            self.blobVHs.append(vh)
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes))
        print('Generating block...')
        block_before_mining = self.nodes[0].getbestblockhash()
        self.generate_helper(self.nodes[0], 1)
        mtp = self.nodes[0].getblockheader(block_before_mining)["mediantime"]
        foundCount = 0
        print('Testing nodes to see if only MAX_DATA_BLOBS blobs exist...')
        for i, blobVH in enumerate(self.blobVHs):
            try:
                blob = self.nodes[1].getnevmblobdata(blobVH)
                if blob['mtp'] == mtp:
                    foundCount += 1
            except Exception:
                pass

        assert_equal(foundCount, MAX_DATA_BLOBS)
        # mine the rest of the blobs
        print('Generating next block...')
        self.generate_helper(self.nodes[0], 1)
        tip = self.nodes[0].getbestblockhash()
        print('Testing nodes to see if MAX_DATA_BLOBS*2 blobs exist...')
        mtp = self.nodes[0].getblockheader(tip)["mediantime"]
        for i, blobVH in enumerate(self.blobVHs):
            try:
                blob = self.nodes[1].getnevmblobdata(blobVH)
                if blob['mtp'] == mtp:
                    foundCount += 1
            except Exception:
                pass

        assert_equal(foundCount, MAX_DATA_BLOBS*2)
        self.generate_helper(self.nodes[0], 3)
        self.sync_without_finality()

    def bump_until_mtp_exceeds(self, cl, expiry_timestamp):
        max_bumps = 20  # avoid infinite loops in case something goes wrong
        bumps = 0
        mtp = self.nodes[0].getblockheader(cl)["mediantime"]
        while True:
            bump_time = (expiry_timestamp - mtp) * 10
            if (bump_time > 150):
                bump_time = 150
            self.bump_mocktime(bump_time)
            print(f"Current MTP: {mtp}, Target expiry: {expiry_timestamp}, Mocktime: {self.mocktime}")
            for i in range(len(self.nodes)):
                force_finish_mnsync(self.nodes[i])

            cl = self.nodes[0].getbestblockhash()
            self.generate(self.nodes[0], 5)
            mtp = self.nodes[0].getblockheader(cl)['mediantime']
            self.sync_without_finality()
            if mtp > expiry_timestamp:
                print(f"Current MTP: {mtp}, Target expiry: {expiry_timestamp}, Mocktime: {self.mocktime}, MTP expiry achieved")
                break
            bumps += 1
            if bumps >= max_bumps:
                raise RuntimeError("Exceeded max mocktime bumps without reaching expiry MTP.")

    def basic_nevm_data(self):
        print('Testing relay in mempool and compact blocks around blobs')
        # test relay with block
        print('Stop node 4 which will be used later to resync blobs to test relay from scratch')
        self.stop_node(4)
        print('Creating a few blobs across nodes...')
        startblockhash = self.nodes[0].getbestblockhash()
        self.nodes[0].syscoincreatenevmblob(secrets.token_hex(55))
        txidData = secrets.token_hex(55)
        txid = self.nodes[1].syscoincreatenevmblob(txidData)['txid']
        txid1Data = secrets.token_hex(55)
        txid1 = self.nodes[0].syscoincreatenevmblob(txid1Data)['txid']
        vhData = secrets.token_hex(55)
        res = self.nodes[3].syscoincreatenevmblob(vhData)
        vh = res['versionhash']
        vhTxid = res['txid']
        self.nodes[3].syscoincreatenevmblob(secrets.token_hex(55))
        print('Checking for duplicate versionhash...')
        assert vhTxid != self.nodes[3].syscoincreaterawnevmblob(vh, vhData)['txid']
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes[0:4]))
        self.nodes[3].syscoincreatenevmblob(secrets.token_hex(55))['txid']
        print('Generating blocks without waiting for mempools to sync...')
        # Mine on ZMQ-enabled node to avoid NEVM-data validation divergence.
        self.generate_helper(self.nodes[0], 5, sync_fun=self.no_op, nodes=self.nodes[0:4])
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes[0:4]))
        self.generate_helper(self.nodes[0], 5, sync_fun=self.no_op, nodes=self.nodes[0:4])
        print('Check for consistency...')
        self.nodes[3].syscoincreatenevmblob(secrets.token_hex(55))
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes[0:4]))
        self.nodes[3].syscoincreatenevmblob(secrets.token_hex(55))
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes[0:4]))
        assert_equal(self.nodes[0].getnevmblobdata(txid, True)['data'], txidData)
        assert_equal(self.nodes[1].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[1].getnevmblobdata(txid, True)['data'], txidData)
        # test relay before block creation
        print('Create more blobs...')
        self.nodes[0].syscoincreatenevmblob(secrets.token_hex(55))
        self.nodes[0].syscoincreatenevmblob(secrets.token_hex(55))
        self.nodes[0].syscoincreatenevmblob(secrets.token_hex(55))
        self.nodes[0].syscoincreatenevmblob(secrets.token_hex(55))
        self.nodes[0].syscoincreatenevmblob(secrets.token_hex(55))
        data = secrets.token_hex(55)
        self.nodes[0].syscoincreatenevmblob(data)
        self.nodes[0].syscoincreatenevmblob(vhData, True)
        self.nodes[0].syscoincreatenevmblob(data, True)
        self.nodes[0].syscoincreatenevmblob(data, True)
        self.nodes[0].syscoincreatenevmblob(data, True)
        for i in range(0, 33):
            blobDataMax = secrets.token_hex(MAX_NEVM_DATA_BLOB)
            self.nodes[0].syscoincreatenevmblob(blobDataMax)
        print('Generating blocks after waiting for mempools to sync...')
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes[0:4]))
        self.generate_helper(self.nodes[0], 5, sync_fun=self.no_op, nodes=self.nodes[0:4])
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes[0:4]))
        print('Test reindex...')
        self.restart_node(1, extra_args=["-mocktime=" + str(self.mocktime), '-reindex', *self.extra_args[1]])
        force_finish_mnsync(self.nodes[1])
        for i in range(len(self.nodes[0:4])):
            if i != 1:
                self.connect_nodes(i, 1, wait_for_connect=False)
                self.connect_nodes(1, i, wait_for_connect=False)
        self.generate_helper(self.nodes[0], 5, sync_fun=self.no_op, nodes=self.nodes[0:4])
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes[0:4]))
        assert_equal(self.nodes[1].getnevmblobdata(txid, True)['data'], txidData)
        assert_equal(self.nodes[1].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[1].getnevmblobdata(txid1, True)['data'], txid1Data)
        mtp = self.nodes[1].getnevmblobdata(txid1)['mtp']
        print('Start node 4...')
        self.start_node(4, extra_args=["-mocktime=" + str(self.mocktime), *self.extra_args[4]])
        force_finish_mnsync(self.nodes[4])
        for i in range(len(self.nodes)):
            if i != 4:
                self.connect_nodes(i, 4, wait_for_connect=False)
                self.connect_nodes(4, i, wait_for_connect=False)
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes))
        assert_equal(self.nodes[4].getnevmblobdata(txid, True)['data'], txidData)
        assert_equal(self.nodes[4].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[4].getnevmblobdata(txid1, True)['data'], txid1Data)
        # SYSCOIN: reindex and offline catch-up must not synthesize finality
        # from this deliberately undersized operator set.
        self.generate_helper(self.nodes[0], 5)
        self.sync_without_finality()
        self.assert_blob_is_not_chainlocked(vh)
        print('Test blob expiry...')
        expiry_timestamp = (mtp + NEVM_DATA_EXPIRE_TIME)
        bump_to_expiry = expiry_timestamp - self.mocktime
        self.bump_mocktime(bump_to_expiry-1) # right before expiry
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        self.generate(self.nodes[0], 5)
        self.sync_without_finality()
        assert_equal(self.nodes[3].getnevmblobdata(txid, True)['data'], txidData)
        assert_equal(self.nodes[2].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[3].getnevmblobdata(txid1, True)['data'], txid1Data)
        self.bump_mocktime(3) # push median time over expiry
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        cl = self.generate(self.nodes[0], 10)[-6]
        self.sync_without_finality()
        self.bump_until_mtp_exceeds(cl, expiry_timestamp)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, txid)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, txid1)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[4].getnevmblobdata, txid)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[2].getnevmblobdata, txid1)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[1].getnevmblobdata, txid1)
        # vh got recreated so its MTP was updated to a later time
        assert_equal(self.nodes[2].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[3].getnevmblobdata(vh, True)['data'], vhData)
        nowblockhash = self.nodes[0].getbestblockhash()
        print('Checking NEVM data reorg without fabricated PQ finality')
        print('Invalidating back to the original blockhash {}'.format(startblockhash))
        self.nodes[0].invalidateblock(startblockhash)
        print('Reconsidering block')
        self.nodes[0].reconsiderblock(startblockhash)
        assert_equal(self.nodes[0].getbestblockhash(), nowblockhash)
        assert_equal(self.nodes[2].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[3].getnevmblobdata(vh, True)['data'], vhData)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, txid)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, txid1)
        self.generate_helper(self.nodes[0], 5)
        self.sync_without_finality()
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, txid)
        assert_equal(self.nodes[0].getnevmblobdata(vh, True)['data'], vhData)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, txid1)
        print('Checking for invalid versionhash...')
        assert_raises_rpc_error(-32602, "Invalid version hash length", self.nodes[3].syscoincreaterawnevmblob, secrets.token_hex(55), secrets.token_hex(55))
        print('Expire updated blob...')
        mtp = self.nodes[0].getnevmblobdata(vh)['mtp']
        expiry_timestamp = (mtp + NEVM_DATA_EXPIRE_TIME)
        cl = self.nodes[0].getbestblockhash()
        self.bump_until_mtp_exceeds(cl, expiry_timestamp)
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        self.generate(self.nodes[0], 5)
        self.sync_without_finality()
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, vh)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, txid)
        assert_raises_rpc_error(-32602, 'Could not find blob information for versionhash', self.nodes[0].getnevmblobdata, txid1)

    def _start_nevm_zmq_responder(self):
        import zmq

        self._zmq_running = True
        self._zmq_connect_count = 0
        self._zmq_connect_events = []
        self._zmq_ctx = zmq.Context()
        self._zmq_ready = Event()
        self._zmq_error = None

        def _loop():
            sock = None
            try:
                # ZeroMQ sockets are thread-affine. Create, use, and close the
                # REP socket in this worker instead of crossing thread bounds.
                sock = self._zmq_ctx.socket(zmq.REP)
                sock.setsockopt(zmq.RCVTIMEO, 1000)
                sock.setsockopt(zmq.SNDTIMEO, 1000)
                sock.bind("tcp://127.0.0.1:29555")
                self._zmq_ready.set()
                while self._zmq_running:
                    try:
                        parts = sock.recv_multipart()
                    except zmq.Again:
                        continue
                    if not parts:
                        continue
                    topic = parts[0]
                    if topic == b"nevmcomms":
                        sock.send_multipart([b"nevmcomms", b"ack"])
                    elif topic == b"nevmblock":
                        h = hash256(str(random.randint(-0x80000000, 0x7FFFFFFF)).encode())
                        u = uint256_from_str(h)
                        nevm_block = CNEVMBlock()
                        nevm_block.nBlockHash = u
                        nevm_block.nTxRoot = u
                        nevm_block.nReceiptRoot = u
                        nevm_block.vchNEVMBlockData = b"nevmblock"
                        sock.send_multipart([b"nevmblock", nevm_block.serialize()])
                    elif topic == b"nevmblockinfo":
                        # Regtest does not attach an external NEVM chain. Avoid
                        # a re-entrant RPC while node 0 is waiting for this REP
                        # response, which can deadlock the fixture at shutdown.
                        # SYSCOIN: Zero applied blocks have no paired Syscoin
                        # tip; the third frame is the protocol's null hash.
                        sock.send_multipart(
                            [b"nevmblockinfo", b"0", b"0" * 64]
                        )
                    elif topic == b"nevmconnect":
                        self._zmq_connect_count += 1
                        try:
                            nevm_connect = CNEVMBlockConnect()
                            nevm_connect.deserialize(BytesIO(parts[1]))
                            self._zmq_connect_events.append((nevm_connect.sysblockhash, nevm_connect.btcprevhash))
                        except Exception:
                            pass
                        sock.send_multipart([b"nevmconnect", b"connected"])
                    elif topic == b"nevmdisconnect":
                        sock.send_multipart([b"nevmdisconnect", b"disconnected"])
                    else:
                        sock.send_multipart([topic, b"ack"])
            except Exception as e:
                self._zmq_error = e
                self._zmq_ready.set()
            finally:
                if sock is not None:
                    sock.close(linger=0)

        self._zmq_thread = Thread(target=_loop, daemon=True)
        self._zmq_thread.start()
        if not self._zmq_ready.wait(timeout=10):
            self._zmq_running = False
            raise RuntimeError("Timed out starting the NEVM ZMQ responder")
        if self._zmq_error is not None:
            self._zmq_thread.join(timeout=5)
            self._zmq_ctx.destroy(linger=0)
            raise RuntimeError("Failed to start the NEVM ZMQ responder") from self._zmq_error

    def _stop_nevm_zmq_responder(self):
        self._zmq_running = False
        if hasattr(self, "_zmq_thread"):
            self._zmq_thread.join(timeout=5)
            if self._zmq_thread.is_alive():
                raise RuntimeError("Timed out stopping the NEVM ZMQ responder")
        if hasattr(self, "_zmq_ctx"):
            self._zmq_ctx.destroy(linger=0)
        if self._zmq_error is not None:
            raise RuntimeError("NEVM ZMQ responder failed") from self._zmq_error

    def run_test(self):
        self._start_nevm_zmq_responder()
        try:
            # Enable ZMQ NEVM publisher only after responder is up to avoid
            # startup-time RPC stalls in framework setup_network mining.
            self.extra_args[0].append("-zmqpubnevm=tcp://127.0.0.1:29555")
            self.extra_args[0].append("-debug=zmq")
            self.restart_node(0, self.extra_args[0])
            self.nodes[1].createwallet("")
            self.nodes[2].createwallet("")
            self.nodes[3].createwallet("")
            for i in range(len(self.nodes)):
                force_finish_mnsync(self.nodes[i])
            for i in range(0, len(self.nodes)):
                for j in range(i, len(self.nodes)):
                    self.connect_nodes(i, j, wait_for_connect=False)
            self.generate_helper(self.nodes[0], 10)
            self.sync_blocks(self.nodes, timeout=60)
            self.nodes[0].spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
            self.wait_for_sporks_same()

            # SYSCOIN: legacy DKG formation was removed. Four operators are
            # intentionally insufficient for the fixed 400/267 PQ profile.
            self.log.info("Checking that the undersized fixture fails closed")
            self.generate_helper(self.nodes[0], 5)
            self.sync_without_finality()
            # Keep mining on ZMQ-enabled node so NEVM data output is produced deterministically.
            self.generate_helper(self.nodes[0], 5)
            self.wait_until(lambda: self.sync_blocks_helper(self.nodes))
            self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1)
            self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1)
            self.nodes[0].sendtoaddress(self.nodes[3].getnewaddress(), 1)
            self.generate_helper(self.nodes[0], 5)
            self.wait_until(lambda: self.sync_blocks_helper(self.nodes))
            # PQ setup can take longer in wall time than mocktime advances.
            # Catch up so peer inventory timers created during startup are due
            # before this test starts measuring transaction relay.
            self.bump_mocktime(max(1, int(time.time()) - self.mocktime + 1))
            self.nevm_data_max_size_blob()
            self.nevm_data_block_max_blobs()
            self.basic_nevm_data()
        finally:
            self._stop_nevm_zmq_responder()


if __name__ == '__main__':
    NEVMDataTest().main()
