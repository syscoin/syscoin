#!/usr/bin/env python3
# Copyright (c) 2015-2020 The Dash Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test deterministic masternodes
#
from test_framework.blocktools import create_block, create_coinbase, get_masternode_payment, add_witness_commitment
from test_framework.messages import CTransaction, from_hex, COIN, CTxOut
from test_framework.test_framework import SyscoinTestFramework
from test_framework.util import p2p_port, Decimal, force_finish_mnsync, assert_equal, get_rpc_proxy, MAX_INITIAL_BROADCAST_DELAY
class Masternode(object):
    pass

class DIP3Test(SyscoinTestFramework):
    def add_options(self, parser):
        # This test is descriptor-only; do not expose legacy wallet mode.
        self.add_wallet_options(parser, descriptors=True, legacy=False)

    # SYSCOIN BEGIN: PQ-sized deterministic-MN test topology.
    def set_test_params(self):
        # No prebuilt PQ registry fixture exists for this dynamically mined
        # chain. Five prepared records are enough to retain the collateral
        # removal, reorg, and replacement matrix. Only the payment-eligible
        # record needs a live MN process; PQ lifecycle behavior has its own
        # focused functional test.
        self.num_initial_mn = 4
        self.num_nodes = 2
        self.setup_clean_chain = True
    # SYSCOIN END: PQ-sized deterministic-MN test topology.

        self.extra_args = ["-sporkkey=cVpF924EspNh8KjYsfhgY96mmxvT6DgdWiTYMtMjuM74hJaU5psW"]
        self.extra_args += ["-mncollateral=100"]

    def skip_test_if_missing_module(self):
        if self.options.descriptors is not True:
            self.log.info("Deterministic MN test forces descriptor wallets")
        self.options.descriptors = True
        self.default_wallet_name = "default_wallet"
        self.skip_if_no_wallet()

    # SYSCOIN BEGIN: Defer governance until PQ registry preparation.
    def setup_network(self):
        self.add_nodes(1)
        self.start_controller_node()
        # This chain must reach DIP3 before PQ registry preparation starts.
        # Superblocks cannot be evaluated against PQ governance until then.
        self.nodes[0].spork("SPORK_9_SUPERBLOCKS_ENABLED", 4070908800)
    # SYSCOIN END: Defer governance until PQ registry preparation.

    def start_controller_node(self):
        self.log.info("starting controller node")
        self.start_node(0, extra_args=self.extra_args)
        force_finish_mnsync(self.nodes[0])
        for i in range(1, self.num_nodes):
            if i < len(self.nodes) and self.nodes[i] is not None and self.nodes[i].process is not None:
                self.connect_nodes(i, 0)

    def stop_controller_node(self):
        self.log.info("stopping controller node")
        self.stop_node(0)

    def restart_controller_node(self):
        self.stop_controller_node()
        self.start_controller_node()

    # SYSCOIN BEGIN: Reindex legacy history into the PQ preparation profile.
    def configure_pq_preparation(self):
        anchor = self.nodes[0].protx_migration_info()
        assert_equal(anchor['height'], self.nodes[0].getblockcount())
        registration_cutoff_blocks = 288
        # SYSCOIN: roster membership is sampled only after root registration closes.
        roster_snapshot_lag = 288
        assert registration_cutoff_blocks >= roster_snapshot_lag
        self.extra_args += [
            '-pqpreparationheight=%d' % anchor['height'],
            '-pqchainlockepochorigin=1440',
            '-pqregistrationcutoffblocks=%d' % registration_cutoff_blocks,
            '-pqrostersnapshotlag=%d' % roster_snapshot_lag,
            '-pqfuturehorizonepochs=8',
            '-pqfinalitypreparation=1',
            # SYSCOIN: This broad replay/state test needs PQ registry behavior,
            # while the focused lifecycle test owns the real 65,536-leaf tree.
            '-pqoperatorcommitmentteststub=1',
        ]
        self.stop_controller_node()
        self.nodes[0].extra_args = list(self.extra_args)
        self.start_node(0, extra_args=self.extra_args + ['-reindex'])
        # The manual restart replaces the harness wallet arguments along with
        # the migration profile, so restore the controller wallet explicitly.
        if self.default_wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(self.default_wallet_name)
        force_finish_mnsync(self.nodes[0])
        assert_equal(self.nodes[0].protx_migration_info(), anchor)
        # The reindexed chain now has a PQ registry at the active tip;
        # restore normal superblock enforcement for the remainder of the test.
        self.nodes[0].spork("SPORK_9_SUPERBLOCKS_ENABLED", 0)

        # Exercise a second node's structural replay before expensive PQ
        # authorization blocks so a registry replay regression cannot be
        # hidden by crypto-test timing.
        self.add_nodes(1, offset=1)
        self.start_node(1, extra_args=self.extra_args)
        self.connect_nodes(1, 0)
        self.sync_blocks(self.nodes[:2], timeout=120)
        assert_equal(self.nodes[1].getbestblockhash(), anchor['blockHash'])
        assert_equal(self.nodes[1].protx_migration_info(), anchor)
        self.stop_node(1)
    # SYSCOIN END: Reindex legacy history into the PQ preparation profile.

    def run_test(self):
        if self.is_wallet_compiled():
            self.nodes[0].createwallet(self.default_wallet_name, descriptors=True)
        self.log.info("funding controller node")
        while self.nodes[0].getbalance() < (self.num_initial_mn + 3) * 100:
            self.generatetoaddress(self.nodes[0], 10, self.nodes[0].getnewaddress()) # generate enough for collaterals
        self.log.info("controller node has {} syscoin".format(self.nodes[0].getbalance()))
        # SYSCOIN BEGIN: Transition the historical DIP3 chain into PQ activation.
        # Preserve the historical DIP3 activation boundary before starting
        # private post-quantum registry preparation.
        self.log.info("testing rejection of ProTx before dip3 activation")
        assert self.nodes[0].getblockchaininfo()['blocks'] < 432
        mns = []

        self.log.info("creating collateral for mn-before-dip3")
        before_dip3_mn = self.prepare_mn(
            self.nodes[0], 1, 'mn-before-dip3')
        self.create_mn_collateral(self.nodes[0], before_dip3_mn)
        mns.append(before_dip3_mn)

        self.generate(
            self.nodes[0], 432 - self.nodes[0].getblockcount())
        assert_equal(self.nodes[0].getblockcount(), 432)
        self.log.info("mining final block for DIP3 activation")
        self.generate(self.nodes[0], 1)
        self.sync_blocks(self.nodes, timeout=120)

        self.configure_pq_preparation()
        self.register_mn(self.nodes[0], before_dip3_mn)
        self.activate_payment_mn(self.nodes[0], before_dip3_mn)
        self.activate_pq_profile()
        self.nodes[0].protx_update_service(
            before_dip3_mn.protx_hash,
            '127.0.0.1:%d' % before_dip3_mn.p2p_port,
            before_dip3_mn.operatorKey, "", "", before_dip3_mn.fundsAddr)
        self.generate(self.nodes[0], 1, sync_fun=self.no_op)
        self.start_mn(before_dip3_mn)
        # SYSCOIN END: Transition the historical DIP3 chain into PQ activation.

        self.log.info("registering inactive list-only MNs")
        for i in range(0, self.num_initial_mn):
            mn = self.prepare_mn(self.nodes[0], i + 2, "mn-%d" % i)
            mns.append(mn)

            # let a few of the protx MNs refer to the existing collaterals
            fund = (i % 2) == 0
            if fund:
                self.log.info("register_fund %s" % mn.alias)
                self.register_fund_mn(self.nodes[0], mn)
            else:
                self.log.info("create_collateral %s" % mn.alias)
                self.create_mn_collateral(self.nodes[0], mn)
                self.log.info("register %s" % mn.alias)
                self.register_mn(self.nodes[0], mn)

            self.generate(self.nodes[0], 1)
            self.sync_all()
            self.assert_mnlists(mns)

        # SYSCOIN BEGIN: Preserve the root-bearing MN across spend and reorg coverage.
        self.log.info("test that MNs disappear from the list when the ProTx collateral is spent")
        spend_mns_count = 3
        # Keep the one root-bearing payment MN available after activation;
        # the list-only records intentionally remain payment-ineligible.
        spent_mns = mns[-spend_mns_count:]
        mns_tmp = [] + mns
        dummy_txins = []
        for mn in spent_mns:
            dummy_txin = self.spend_mn_collateral(mn, with_dummy_input_output=True)
            dummy_txins.append(dummy_txin)
            self.generate(self.nodes[0], 1)
            mns_tmp.remove(mn)
            self.assert_mnlists(mns_tmp)

        self.log.info("test that reverting the blockchain on a single node results in the mnlist to be reverted as well")
        for i in range(spend_mns_count):
            self.nodes[0].invalidateblock(self.nodes[0].getbestblockhash())
            mns_tmp.append(spent_mns[spend_mns_count - 1 - i])
            self.assert_mnlist(self.nodes[0], mns_tmp)
        # SYSCOIN END: Preserve the root-bearing MN across spend and reorg coverage.

        self.log.info("cause a reorg with a double spend and check that mnlists are still correct on all nodes")
        self.mine_double_spend(self.nodes[0], dummy_txins, self.nodes[0].getnewaddress(), use_mnmerkleroot_from_tip=True)
        self.generate(self.nodes[0], spend_mns_count)
        self.assert_mnlists(mns_tmp)

        self.log.info("test mn payment enforcement with deterministic MNs")
        for i in range(20):
            node = self.nodes[i % len(self.nodes)]
            self.test_invalid_mn_payment(node)
            self.generate(self.nodes[0], 1)

        self.log.info("testing ProUpServTx")
        payment_mn = mns[0]
        try:
            payment_mn.node.lockunspent(
                False,
                [{'txid': payment_mn.collateral_txid,
                  'vout': payment_mn.collateral_vout}],
                True)
        except Exception:
            pass

        for mn in mns:
            # lock again after reorg above
            try:
                self.nodes[0].lockunspent(False, [{'txid': mn.collateral_txid, 'vout': mn.collateral_vout}], True)
            except Exception:
                pass

        self.test_protx_update_service(payment_mn)

        self.log.info("testing P2SH/multisig for payee addresses")

        # Create 1 of 2 multisig
        addr1 = self.nodes[0].getnewaddress()
        addr2 = self.nodes[0].getnewaddress()

        addr1Obj = self.nodes[0].getaddressinfo(addr1)
        addr2Obj = self.nodes[0].getaddressinfo(addr2)

        multisig = self.nodes[0].createmultisig(1, [addr1Obj['pubkey'], addr2Obj['pubkey']])['address']
        self.update_mn_payee(payment_mn, multisig)
        found_multisig_payee = False
        for i in range(len(mns)):
            bt = self.nodes[0].getblocktemplate({'rules': ['segwit']})
            expected_payee = bt['masternode'][0]['payee']
            expected_amount = bt['masternode'][0]['amount']
            self.generate(self.nodes[0], 1)
            if expected_payee == multisig:
                block = self.nodes[0].getblock(self.nodes[0].getbestblockhash())
                cbtx = self.nodes[0].getrawtransaction(block['tx'][0], 1, self.nodes[0].getbestblockhash())
                for out in cbtx['vout']:
                    if 'address' in out['scriptPubKey']:
                        if expected_payee == out['scriptPubKey']['address'] and int(out['value']*COIN) == expected_amount:
                            found_multisig_payee = True
        assert found_multisig_payee

        self.log.info("testing reusing of collaterals for replaced inactive MNs")
        for i in range(1, len(mns)):
            mn = mns[i]
            # a few of these will actually refer to old ProRegTx internal collaterals,
            # which should work the same as external collaterals
            new_mn = self.prepare_mn(self.nodes[0], mn.idx, mn.alias)
            new_mn.collateral_address = mn.collateral_address
            new_mn.collateral_txid = mn.collateral_txid
            new_mn.collateral_vout = mn.collateral_vout

            self.register_mn(self.nodes[0], new_mn)
            mns[i] = new_mn
            self.generate(self.nodes[0], 1)
            self.assert_mnlists(mns)

        # SYSCOIN BEGIN: Bound payout-input selection after PQ test acceleration.
        self.log.info("testing masternode status updates")
        # Use a fresh wallet-controlled payout after the multisig case. The
        # original address has accumulated thousands of tiny test payments;
        # selecting all of them would obscure the empty fee-source behavior
        # with an unrelated standard-transaction weight failure.
        payment_mn.rewards_address = self.nodes[0].getnewaddress()
        self.update_mn_payee(payment_mn, payment_mn.rewards_address)
        # change voting address and see if changes are reflected in `masternode status` rpc output
        mn = payment_mn
        node = self.nodes[0]
        old_dmnState = mn.node.masternode_status()["dmnState"]
        old_voting_address = old_dmnState["votingAddress"]
        new_voting_address = node.getnewaddress()
        assert old_voting_address != new_voting_address
        # also check if funds from payout address are used when no fee source address is specified
        node.sendtoaddress(mn.rewards_address, 0.001)
        self.generate(node, 1)
        node.protx_update_registrar(mn.protx_hash, "", new_voting_address, "")
        self.generate(node, 1)
        # SYSCOIN END: Bound payout-input selection after PQ test acceleration.
        new_dmnState = mn.node.masternode_status()["dmnState"]
        new_voting_address_from_rpc = new_dmnState["votingAddress"]
        assert new_voting_address_from_rpc == new_voting_address
        # make sure payoutAddress is the same as before
        assert old_dmnState["payoutAddress"] == new_dmnState["payoutAddress"]

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
        mn.chainlockSeed = operator_keys['chainlockSeed']

        return mn

    def create_mn_collateral(self, node, mn):
        mn.collateral_address = node.getnewaddress()
        mn.collateral_txid = node.sendtoaddress(mn.collateral_address, 100)
        mn.collateral_vout = -1
        self.generate(node, 1)

        rawtx = node.getrawtransaction(mn.collateral_txid, 1)
        for txout in rawtx['vout']:
            if txout['value'] == Decimal(100):
                mn.collateral_vout = txout['n']
                break
        assert mn.collateral_vout != -1
        # lock after creating collateral
        node.lockunspent(False, [{'txid': mn.collateral_txid, 'vout': mn.collateral_vout}], True)

    # register a protx MN and also fund it (using collateral inside ProRegTx)
    def register_fund_mn(self, node, mn):
        node.sendtoaddress(mn.fundsAddr, 100.001)
        mn.collateral_address = node.getnewaddress()
        mn.rewards_address = node.getnewaddress()

        mn.protx_hash = node.protx_register_fund( mn.collateral_address, '127.0.0.1:%d' % mn.p2p_port, mn.ownerAddr, "", mn.votingAddr, 0, mn.rewards_address, mn.fundsAddr)
        mn.collateral_txid = mn.protx_hash
        mn.collateral_vout = -1

        rawtx = node.getrawtransaction(mn.collateral_txid, 1)
        for txout in rawtx['vout']:
            if txout['value'] == Decimal(100):
                mn.collateral_vout = txout['n']
                break
        assert mn.collateral_vout != -1

    # create a protx MN which refers to an existing collateral
    def register_mn(self, node, mn):
        node.sendtoaddress(mn.fundsAddr, 0.001)
        mn.rewards_address = node.getnewaddress()

        mn.protx_hash = node.protx_register(mn.collateral_txid, mn.collateral_vout, '127.0.0.1:%d' % mn.p2p_port, mn.ownerAddr, "", mn.votingAddr, 0, mn.rewards_address, mn.fundsAddr)

    # SYSCOIN BEGIN: Register one real root and activate the PQ test profile.
    def activate_payment_mn(self, node, mn):
        # The migration bootstrap verifier occupying node 1 is deliberately
        # stopped until start_mn() reuses that slot.
        self.generate(node, 1, sync_fun=self.no_op)
        # Building the fixed 65,536-leaf scheduled-WOTS commitment can exceed the
        # ordinary RPC timeout on low-core test hosts. The focused operator
        # lifecycle test owns rotation and mempool-auth coverage; this broad
        # test builds exactly one root solely to retain payment enforcement.
        registration_rpc = get_rpc_proxy(
            node.url, node.index, timeout=600,
            coveragedir=node.coverage_dir)
        registration_rpc.protx_register_operator_key(
            mn.protx_hash, mn.operatorKey, mn.chainlockSeed, mn.fundsAddr)
        self.generate(node, 1, sync_fun=self.no_op)

    def activate_pq_profile(self):
        predecessor_height = 2304
        assert self.nodes[0].getblockcount() <= predecessor_height
        self.generatetoaddress(
            self.nodes[0],
            predecessor_height - self.nodes[0].getblockcount(),
            self.nodes[0].getnewaddress(), sync_fun=self.no_op)
        predecessor_hash = self.nodes[0].getblockhash(predecessor_height)
        self.extra_args = [
            arg for arg in self.extra_args
            if arg != '-pqfinalitypreparation=1'
        ] + [
            '-pqactivationheight=%d' % (predecessor_height + 1),
            '-pqbtcccandidateorigin=1000000',
            '-pqbtccreceiptanchorheight=%d' % predecessor_height,
            '-pqbtccreceiptanchorblockhash=%s' % predecessor_hash,
            '-pqbtccreceiptanchorcursorheight=-1',
            '-pqbtccreceiptanchorcursorsyshash=%s' % ('0' * 64),
            '-pqbtccreceiptanchorcursorbtchash=%s' % ('0' * 64),
            '-pqbtccreceiptanchorstatehash=%s' % ('0' * 64),
        ]
        self.stop_controller_node()
        self.nodes[0].extra_args = list(self.extra_args)
        self.start_node(0, extra_args=self.extra_args + ['-reindex'])
        if self.default_wallet_name not in self.nodes[0].listwallets():
            self.nodes[0].loadwallet(self.default_wallet_name)
        force_finish_mnsync(self.nodes[0])
        assert_equal(self.nodes[0].getblockcount(), predecessor_height)
        assert_equal(self.nodes[0].getbestblockhash(), predecessor_hash)
    # SYSCOIN END: Register one real root and activate the PQ test profile.

    def start_mn(self, mn):
        start_idx = len(self.nodes) - 1
        # SYSCOIN add offset and add nodes individually with offset and custom args
        for idx in range(start_idx, mn.idx):
            self.add_nodes(1, offset=idx+1)

        extra_args = [
            '-masternodeslhprivkey=%s' % mn.operatorKey,
            '-masternodechainlockseed=%s' % mn.chainlockSeed,
        ]
        self.start_node(mn.idx, extra_args = self.extra_args + extra_args)
        force_finish_mnsync(self.nodes[mn.idx])
        mn.node = self.nodes[mn.idx]
        self.connect_nodes(mn.node.index, 0)
        self.nodes[mn.idx].mockscheduler(MAX_INITIAL_BROADCAST_DELAY)
        self.sync_all()

    def spend_mn_collateral(self, mn, with_dummy_input_output=False):
        return self.spend_input(mn.collateral_txid, mn.collateral_vout, 100, with_dummy_input_output)

    def update_mn_payee(self, mn, payee):
        self.nodes[0].sendtoaddress(mn.fundsAddr, 0.001)
        self.nodes[0].protx_update_registrar(mn.protx_hash, '', '', payee, mn.fundsAddr)
        self.generate(self.nodes[0], 1)
        info = self.nodes[0].protx_info(mn.protx_hash)
        assert info['state']['payoutAddress'] == payee

    def test_protx_update_service(self, mn):
        self.nodes[0].sendtoaddress(mn.fundsAddr, 0.001)
        self.nodes[0].protx_update_service( mn.protx_hash, '127.0.0.2:%d' % mn.p2p_port, mn.operatorKey, "", "", mn.fundsAddr)
        self.generate(self.nodes[0], 1)
        for node in self.nodes:
            protx_info = node.protx_info( mn.protx_hash)
            mn_list = node.masternode_list()
            assert_equal(protx_info['state']['service'], '127.0.0.2:%d' % mn.p2p_port)
            assert_equal(mn_list['%s-%d' % (mn.collateral_txid, mn.collateral_vout)]['address'], '127.0.0.2:%d' % mn.p2p_port)

        # undo
        self.nodes[0].protx_update_service(mn.protx_hash, '127.0.0.1:%d' % mn.p2p_port, mn.operatorKey, "", "", mn.fundsAddr)
        self.generate(self.nodes[0], 1)

    def assert_mnlists(self, mns):
        for node in self.nodes:
            self.assert_mnlist(node, mns)

    def assert_mnlist(self, node, mns):
        if not self.compare_mnlist(node, mns):
            expected = []
            for mn in mns:
                expected.append('%s-%d' % (mn.collateral_txid, mn.collateral_vout))
            self.log.error('mnlist: ' + str(node.masternode_list('status')))
            self.log.error('expected: ' + str(expected))
            raise AssertionError("mnlists does not match provided mns")

    def compare_mnlist(self, node, mns):
        mnlist = node.masternode_list('status')
        for mn in mns:
            s = '%s-%d' % (mn.collateral_txid, mn.collateral_vout)
            in_list = s in mnlist
            if not in_list:
                return False
            mnlist.pop(s, None)
        if len(mnlist) != 0:
            return False
        return True

    def spend_input(self, txid, vout, amount, with_dummy_input_output=False):
        # with_dummy_input_output is useful if you want to test reorgs with double spends of the TX without touching the actual txid/vout
        address = self.nodes[0].getnewaddress()

        txins = [
            {'txid': txid, 'vout': vout}
        ]
        targets = {address: amount}

        dummy_txin = None
        if with_dummy_input_output:
            dummyaddress = self.nodes[0].getnewaddress()
            unspent = self.nodes[0].listunspent(110)
            for u in unspent:
                if u['amount'] > Decimal(1):
                    dummy_txin = {'txid': u['txid'], 'vout': u['vout']}
                    txins.append(dummy_txin)
                    targets[dummyaddress] = float(u['amount'] - Decimal(0.0001))
                    break

        rawtx = self.nodes[0].createrawtransaction(txins, targets)
        rawtx = self.nodes[0].fundrawtransaction(rawtx)['hex']
        rawtx = self.nodes[0].signrawtransactionwithwallet(rawtx)['hex']
        self.nodes[0].sendrawtransaction(rawtx)
        return dummy_txin

    def mine_block(self, node, vtx=None, mn_payee=None, mn_amount=None, use_mnmerkleroot_from_tip=False, expected_error=None):
        if vtx is None:
            vtx = []
        bt = node.getblocktemplate({'rules': ['segwit']})
        height = bt['height']
        tip_hash = bt['previousblockhash']

        coinbasevalue = 50 * COIN
        halvings = int(height / 150)  # regtest
        coinbasevalue >>= halvings

        miner_script = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())['scriptPubKey']
        if mn_payee is None:
            if isinstance(bt['masternode'], list):
                mn_payee = bt['masternode'][0]['script']
            else:
                mn_payee = bt['masternode']['script']
        # we can't take the masternode payee amount from the template here as we might have additional fees in vtx
        new_fees = 0
        for tx in vtx:
            in_value = 0
            out_value = 0
            for txin in tx.vin:
                txout = node.gettxout("%064x" % txin.prevout.hash, txin.prevout.n, False)
                in_value += int(txout['value'] * COIN)
            for txout in tx.vout:
                out_value += txout.nValue
            new_fees += in_value - out_value


        if mn_amount is None:
            mn_amount = get_masternode_payment(height, coinbasevalue, bt['masternode_collateral_height']) + new_fees/2
        miner_amount = int(coinbasevalue*0.25)
        miner_amount += new_fees/2

        coinbase = CTransaction()
        coinbase.vout.append(CTxOut(int(miner_amount), bytes.fromhex(miner_script)))
        coinbase.vout.append(CTxOut(int(mn_amount), bytes.fromhex(mn_payee)))
        coinbase.vin = create_coinbase(height).vin

        # Recreate mn root as using one in BT would result in invalid merkle roots for masternode lists
        coinbase.nVersion = bt['version_coinbase']
        if len(bt['default_witness_commitment_extra']) != 0:
            coinbase.extraData = bytes.fromhex(bt['default_witness_commitment_extra'])

        coinbase.calc_sha256(with_witness=True)

        # SYSCOIN: Accelerated PQ setup can leave a fast-mined regtest chain
        # ahead of the wall-clock fallback; the template time is MTP-safe.
        block = create_block(int(tip_hash, 16), coinbase, ntime=bt['curtime'])
        block.nVersion = 4
        block.vtx += vtx
        block.hashMerkleRoot = block.calc_merkle_root()
        add_witness_commitment(block)
        block.solve()
        result = node.submitblock(block.serialize().hex())
        if expected_error is not None and result != expected_error:
            raise AssertionError('mining the block should have failed with error %s, but submitblock returned %s' % (expected_error, result))
        elif expected_error is None and result is not None:
            raise AssertionError('submitblock returned %s' % (result))

    def mine_double_spend(self, node, txins, target_address, use_mnmerkleroot_from_tip=False):
        amount = Decimal(0)
        for txin in txins:
            txout = node.gettxout(txin['txid'], txin['vout'], False)
            amount += txout['value']
        amount -= Decimal("0.001") # fee

        rawtx = node.createrawtransaction(txins, {target_address: amount})
        rawtx = node.signrawtransactionwithwallet(rawtx)['hex']
        tx = from_hex(CTransaction(), rawtx)

        self.mine_block(node, [tx], use_mnmerkleroot_from_tip=use_mnmerkleroot_from_tip)

    def test_invalid_mn_payment(self, node):
        mn_payee = self.nodes[0].getaddressinfo(self.nodes[0].getnewaddress())['scriptPubKey']
        self.mine_block(node, mn_payee=mn_payee, expected_error='bad-cb-payee')
        self.mine_block(node, mn_amount=1, expected_error='bad-cb-payee')

if __name__ == '__main__':
    DIP3Test().main()
