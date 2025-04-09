#!/usr/bin/env python3
# Copyright (c) 2019-2020 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
import secrets
from test_framework.test_framework import DashTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error, force_finish_mnsync
from test_framework.messages import NEVM_DATA_EXPIRE_TIME, MAX_DATA_BLOBS, MAX_NEVM_DATA_BLOB

class NEVMDataTest(DashTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.set_dash_test_params(5, 4, [["-disablewallet=0","-walletrejectlongchains=0"]] * 5, fast_dip3_enforcement=True)

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()
        self.skip_if_no_bdb()

    def nevm_data_max_size_blob(self):
        print('Testing for max size of a blob (2MB)')
        blobDataMax = secrets.token_hex(MAX_NEVM_DATA_BLOB)
        print('Creating large blob (2MB)...')
        vh = self.nodes[0].syscoincreatenevmblob(blobDataMax)['versionhash']
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes))
        print('Generating block...')
        cl = self.nodes[0].getbestblockhash()
        self.generate_helper(self.nodes[0], 5)
        self.wait_for_chainlocked_block_all_nodes(cl)
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
        print('Trying 2MB * MAX_DATA_BLOBS per block...')
        self.blobVHs = []
        for i in range(0, 33):
            blobDataMax = secrets.token_hex(MAX_NEVM_DATA_BLOB)
            vh = self.nodes[0].syscoincreatenevmblob(blobDataMax)['versionhash']
            self.blobVHs.append(vh)
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes))
        print('Generating block...')
        cl = self.nodes[0].getbestblockhash()
        tip = self.generate(self.nodes[0], 1)[-1]
        rpc_details = self.nodes[0].getblock(tip, True)
        print('Ensure fees will be properly calculated due to the block size being correctly calculated based on PoDA policy (100x factor of blob data)...')
        assert rpc_details["size"] > 670000 and rpc_details["size"]  < 680000
        foundCount = 0
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes))
        print('Testing nodes to see if MAX_DATA_BLOBS blobs exist at 2MB each...')
        for i, blobVH in enumerate(self.blobVHs):
            mpt = 0
            try:
                mpt = self.nodes[1].getnevmblobdata(blobVH)['mpt']
                # mpt > 0 means it got confirmed
                if (mpt > 0):
                    foundCount += 1
            except Exception:
                pass

        assert_equal(foundCount, MAX_DATA_BLOBS)
        print('Generating next block...')
        tip = self.generate(self.nodes[0], 1)[-1]
        rpc_details = self.nodes[0].getblock(tip, True)
        foundCount = 0
        print('Testing nodes to see if MAX_DATA_BLOBS+1 blobs exist...')
        for i, blobVH in enumerate(self.blobVHs):
            mpt = 0
            try:
                mpt = self.nodes[1].getnevmblobdata(blobVH)['mpt']
                # mpt > 0 means it got confirmed
                if (mpt > 0):
                    foundCount += 1
            except Exception:
                pass

        assert_equal(foundCount, MAX_DATA_BLOBS+1)
        self.generate(self.nodes[0], 3)
        self.wait_for_chainlocked_block_all_nodes(cl)

    def nevm_data_block_max_blobs(self):
        print('Testing for max number of blobs in a block (32)')
        self.blobVHs = []
        print('Populate 2 * MAX_DATA_BLOBS blobs in mempool (64)')
        for i in range(0, MAX_DATA_BLOBS*2):
            vh = self.nodes[0].syscoincreatenevmblob(secrets.token_hex(55))['versionhash']
            self.blobVHs.append(vh)
        self.wait_until(lambda: self.sync_mempools_helper(self.nodes))
        print('Generating block...')
        cl = self.nodes[0].getbestblockhash()
        self.generate_helper(self.nodes[0], 1)
        foundCount = 0
        print('Testing nodes to see if only MAX_DATA_BLOBS blobs exist...')
        for i, blobVH in enumerate(self.blobVHs):
            mpt = 0
            try:
                mpt = self.nodes[1].getnevmblobdata(blobVH)['mpt']
                # mpt > 0 means it got confirmed
                if (mpt > 0):
                    foundCount += 1
            except Exception:
                pass

        assert_equal(foundCount, MAX_DATA_BLOBS)
        # clear the rest of the blobs
        print('Generating next block...')
        self.generate_helper(self.nodes[0], 1)
        foundCount = 0
        print('Testing nodes to see if MAX_DATA_BLOBS*2 blobs exist...')
        for i, blobVH in enumerate(self.blobVHs):
            mpt = 0
            try:
                mpt = self.nodes[1].getnevmblobdata(blobVH)['mpt']
                # mpt > 0 means it got confirmed
                if (mpt > 0):
                    foundCount += 1
            except Exception:
                pass

        assert_equal(foundCount, MAX_DATA_BLOBS*2)
        self.generate_helper(self.nodes[0], 3)
        self.wait_for_chainlocked_block_all_nodes(cl)

    def bump_until_mtp_exceeds(self, cl, expiry_timestamp):
        max_bumps = 20  # avoid infinite loops in case something goes wrong
        bumps = 0
        mtp = self.nodes[0].getblockheader(cl)["mediantime"]
        while True:
            self.bump_mocktime(150)
            print(f"Current MTP: {mtp}, Target expiry: {expiry_timestamp}, Mocktime: {self.mocktime}")
            for i in range(len(self.nodes)):
                force_finish_mnsync(self.nodes[i])
            for i in range(len(self.nodes)):
                if i != 1:
                    self.connect_nodes(i, 1, wait_for_connect=False)
                    self.connect_nodes(1, i, wait_for_connect=False)
                if i != 0:
                    self.connect_nodes(i, 0, wait_for_connect=False)
                    self.connect_nodes(1, 0, wait_for_connect=False)
            cl = self.nodes[0].getbestblockhash()
            self.generate(self.nodes[0], 5)
            mtp = self.nodes[0].getblockheader(cl)['mediantime']
            self.wait_for_chainlocked_block_all_nodes(cl)
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
        self.generate_helper(self.nodes[2], 5, sync_fun=self.no_op, nodes=self.nodes[0:4])
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes[0:4]))
        self.generate_helper(self.nodes[2], 5, sync_fun=self.no_op, nodes=self.nodes[0:4])
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
        self.generate_helper(self.nodes[2], 5, sync_fun=self.no_op, nodes=self.nodes[0:4])
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes[0:4]))
        print('Test reindex...')
        self.restart_node(1, extra_args=["-mocktime=" + str(self.mocktime), '-reindex', *self.extra_args[1]])
        force_finish_mnsync(self.nodes[1])
        for i in range(len(self.nodes[0:4])):
            if i != 1:
                self.connect_nodes(i, 1, wait_for_connect=False)
                self.connect_nodes(1, i, wait_for_connect=False)
            if i != 0:
                self.connect_nodes(i, 0, wait_for_connect=False)
                self.connect_nodes(1, 0, wait_for_connect=False)
        self.generate_helper(self.nodes[0], 5, sync_fun=self.no_op, nodes=self.nodes[0:4])
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes[0:3]))
        assert_equal(self.nodes[1].getnevmblobdata(txid, True)['data'], txidData)
        assert_equal(self.nodes[1].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[1].getnevmblobdata(txid1, True)['data'], txid1Data)
        mtp = self.nodes[1].getnevmblobdata(vhTxid)['mpt']
        print('Start node 4...')
        self.start_node(4, extra_args=["-mocktime=" + str(self.mocktime), *self.extra_args[4]])
        force_finish_mnsync(self.nodes[4])
        for i in range(len(self.nodes)):
            if i != 1:
                self.connect_nodes(i, 1, wait_for_connect=False)
                self.connect_nodes(1, i, wait_for_connect=False)
            if i != 0:
                self.connect_nodes(i, 0, wait_for_connect=False)
                self.connect_nodes(1, 0, wait_for_connect=False)
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes))
        assert_equal(self.nodes[4].getnevmblobdata(txid, True)['data'], txidData)
        assert_equal(self.nodes[4].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[4].getnevmblobdata(txid1, True)['data'], txid1Data)
        print('Test blob expiry...')
        expiry_timestamp = (mtp + NEVM_DATA_EXPIRE_TIME)
        bump_to_expiry = expiry_timestamp - self.mocktime
        self.bump_mocktime(bump_to_expiry-1) # right before expiry
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        for i in range(len(self.nodes)):
            if i != 1:
                self.connect_nodes(i, 1, wait_for_connect=False)
                self.connect_nodes(1, i, wait_for_connect=False)
            if i != 0:
                self.connect_nodes(i, 0, wait_for_connect=False)
                self.connect_nodes(1, 0, wait_for_connect=False)
        cl = self.nodes[0].getbestblockhash()
        self.generate(self.nodes[0], 5)
        self.wait_for_chainlocked_block_all_nodes(cl)
        assert_equal(self.nodes[3].getnevmblobdata(txid, True)['data'], txidData)
        assert_equal(self.nodes[2].getnevmblobdata(vh, True)['data'], vhData)
        assert_equal(self.nodes[3].getnevmblobdata(txid1, True)['data'], txid1Data)
        self.bump_mocktime(3) # push median time over expiry
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        cl = self.generate(self.nodes[0], 10)[-6]
        self.wait_for_chainlocked_block_all_nodes(cl)
        self.bump_until_mtp_exceeds(cl, expiry_timestamp)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, txid)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, vh)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, txid1)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[4].getnevmblobdata, txid)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[3].getnevmblobdata, vh)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[2].getnevmblobdata, txid1)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[1].getnevmblobdata, txid1)
        nowblockhash = self.nodes[0].getbestblockhash()
        print('Checking for reorg with chainlocks')
        print('Invalidating back to the original blockhash {}'.format(startblockhash))
        self.nodes[0].invalidateblock(startblockhash)
        print('Reconsidering block')
        self.nodes[0].reconsiderblock(startblockhash)
        assert_equal(self.nodes[0].getbestblockhash(), nowblockhash)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, txid)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, vh)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, txid1)
        cl = self.nodes[0].getbestblockhash()
        self.generate_helper(self.nodes[0], 5)
        self.wait_for_chainlocked_block_all_nodes(cl)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, txid)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, vh)
        assert_raises_rpc_error(-32602, 'Could not find MTP for versionhash', self.nodes[0].getnevmblobdata, txid1)
        print('Checking for invalid versionhash...')
        txidBad = self.nodes[3].syscoincreaterawnevmblob(secrets.token_hex(55), secrets.token_hex(55))['txid']
        # should fail and not propagate due to 'bad-txns-poda-invalid'
        assert_raises_rpc_error(-5, "No such mempool transaction", self.nodes[0].getrawtransaction, txid=txidBad)

    def run_test(self):
        self.nodes[1].createwallet("")
        self.nodes[2].createwallet("")
        self.nodes[3].createwallet("")
        for i in range(len(self.nodes)):
            force_finish_mnsync(self.nodes[i])
        # Connect all nodes to node1 so that we always have the whole network connected
        # Otherwise only masternode connections will be established between nodes, which won't propagate TXs/blocks
        for i in range(len(self.nodes)):
            if i != 1:
                self.connect_nodes(i, 1, wait_for_connect=False)
                self.connect_nodes(1, i, wait_for_connect=False)
            if i != 0:
                self.connect_nodes(i, 0, wait_for_connect=False)
                self.connect_nodes(1, 0, wait_for_connect=False)
        self.generate_helper(self.nodes[0], 10)
        self.sync_blocks(self.nodes, timeout=60*5)
        self.nodes[0].spork("SPORK_17_QUORUM_DKG_ENABLED", 0)
        self.nodes[0].spork("SPORK_19_CHAINLOCKS_ENABLED", 0)
        self.wait_for_sporks_same()

        self.log.info("Mining 4 quorums")
        for i in range(4):
            self.mine_quorum(mod5=True)

        self.wait_for_sporks_same()
        self.log.info("Mine single block, wait for chainlock")
        cl = self.nodes[0].getbestblockhash()
        self.generate_helper(self.nodes[0], 5)
        self.wait_for_chainlocked_block_all_nodes(cl)
        self.generate_helper(self.nodes[1], 5)
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes))
        self.nodes[0].sendtoaddress(self.nodes[1].getnewaddress(), 1)
        self.nodes[0].sendtoaddress(self.nodes[2].getnewaddress(), 1)
        self.nodes[0].sendtoaddress(self.nodes[3].getnewaddress(), 1)
        self.generate_helper(self.nodes[0], 5)
        self.wait_until(lambda: self.sync_blocks_helper(self.nodes))
        self.nevm_data_max_size_blob()
        self.nevm_data_block_max_blobs()
        self.basic_nevm_data()


if __name__ == '__main__':
    NEVMDataTest().main()
