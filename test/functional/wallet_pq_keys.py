#!/usr/bin/env python3
# Copyright (c) 2026 The Syscoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Selective PQ key backup/import, public inventory, and role preservation."""

from test_framework.test_framework import SyscoinTestFramework
from test_framework.util import assert_equal, assert_raises_rpc_error


class WalletPQKeysTest(SyscoinTestFramework):
    def add_options(self, parser):
        self.add_wallet_options(parser)

    def set_test_params(self):
        self.num_nodes = 1
        self.setup_clean_chain = True
        self.wallet_names = []

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    @staticmethod
    def inventory(wallet):
        result = wallet.listpqkeys()
        public_keys = [entry["public_key"] for entry in result]
        assert_equal(len(public_keys), len(set(public_keys)))
        for entry in result:
            assert_equal(set(entry), {
                "public_key", "algorithm", "roles", "has_private_key", "associations"})
            assert_equal(len(entry["public_key"]), 64)
            assert_equal(entry["algorithm"], "SLH-DSA-SHAKE-128s")
            assert_equal(entry["has_private_key"], True)
            assert set(entry["roles"]).issubset({"owner", "voting"})
            assert entry["roles"]
        return {entry["public_key"]: entry for entry in result}

    def run_test(self):
        node = self.nodes[0]
        for name in ("source", "selected", "encrypted"):
            node.createwallet(name, descriptors=self.options.descriptors)
        node.createwallet(
            "watchonly", disable_private_keys=True, blank=True,
            descriptors=self.options.descriptors)
        source = node.get_wallet_rpc("source")
        selected = node.get_wallet_rpc("selected")
        encrypted = node.get_wallet_rpc("encrypted")
        watchonly = node.get_wallet_rpc("watchonly")

        assert_equal(source.listpqkeys(), [])
        owner_public = source.protx_generate_owner_key()
        voting_public = source.protx_generate_voting_key()
        extra_owner = source.protx_generate_owner_key()
        ordinary_address = source.getnewaddress()
        initial = self.inventory(source)
        assert_equal(set(initial), {owner_public, voting_public, extra_owner})
        assert_equal(initial[owner_public]["roles"], ["owner"])
        assert_equal(initial[voting_public]["roles"], ["voting"])
        assert all(entry["associations"] == [] for entry in initial.values())

        self.log.info("Selective backups preserve PQ roles without exporting other wallet keys")
        owner_record = source.dumppqkey(owner_public)
        voting_record = source.dumppqkey(voting_public)
        assert owner_record.startswith("syspqkey1:")
        assert voting_record.startswith("syspqkey1:")
        assert owner_record != voting_record
        assert_equal(selected.importpqkey(owner_record), {
            "public_key": owner_public, "roles": ["owner"]})
        selected_inventory = self.inventory(selected)
        assert_equal(set(selected_inventory), {owner_public})
        assert_equal(selected_inventory[owner_public], initial[owner_public])
        assert_equal(selected.getaddressinfo(ordinary_address)["ismine"], False)
        assert_raises_rpc_error(None, None, selected.dumppqkey, voting_public)
        assert_equal(selected.importpqkey(voting_record), {
            "public_key": voting_public, "roles": ["voting"]})
        # Repeated imports are idempotent and retain each independent role.
        assert_equal(selected.importpqkey(owner_record), {
            "public_key": owner_public, "roles": ["owner"]})
        assert_equal(set(self.inventory(selected)), {owner_public, voting_public})
        assert_equal(selected.dumppqkey(owner_public), owner_record)
        assert_equal(selected.dumppqkey(voting_public), voting_record)
        assert all(entry["associations"] == [] for entry in self.inventory(selected).values())
        assert_equal(node.getrawmempool(), [])
        assert_equal(node.getblockcount(), 0)

        self.log.info("Malformed exports fail atomically, and public-only wallets cannot import secrets")
        before = self.inventory(selected)
        corrupt = owner_record[:-1] + ("1" if owner_record[-1] != "1" else "2")
        for malformed in ("", owner_public, "00" * 64, "syspqkey1:0OIl", corrupt,
                          "syspqkey2:" + owner_record.split(":", 1)[1],
                          owner_record + "extra"):
            assert_raises_rpc_error(None, None, selected.importpqkey, malformed)
            assert_equal(self.inventory(selected), before)
        assert_raises_rpc_error(None, None, watchonly.importpqkey, owner_record)
        assert_raises_rpc_error(None, None, watchonly.importpqkey, voting_record)
        assert_equal(watchonly.listpqkeys(), [])

        self.log.info("Locked inventory remains public while secret export and import require unlock")
        passphrase = "pq-selective-backup-passphrase"
        source.encryptwallet(passphrase)
        assert_equal(self.inventory(source), initial)
        assert_raises_rpc_error(-13, "walletpassphrase", source.dumppqkey, owner_public)
        assert_raises_rpc_error(-13, "walletpassphrase", source.dumppqkey, voting_public)
        source.walletpassphrase(passphrase, 120)
        assert_equal(source.dumppqkey(owner_public), owner_record)
        source.walletlock()

        encrypted.encryptwallet(passphrase)
        assert_raises_rpc_error(-13, "walletpassphrase", encrypted.importpqkey, owner_record)
        assert_equal(encrypted.listpqkeys(), [])
        encrypted.walletpassphrase(passphrase, 120)
        encrypted.importpqkey(owner_record)
        encrypted.importpqkey(voting_record)
        encrypted.walletlock()
        expected = self.inventory(encrypted)
        node.unloadwallet("encrypted")
        node.loadwallet("encrypted")
        encrypted = node.get_wallet_rpc("encrypted")
        assert_equal(self.inventory(encrypted), expected)
        assert_raises_rpc_error(-13, "walletpassphrase", encrypted.dumppqkey, owner_public)
        encrypted.walletpassphrase(passphrase, 120)
        assert_equal(encrypted.dumppqkey(owner_public), owner_record)
        assert_equal(encrypted.dumppqkey(voting_public), voting_record)

        self.log.info("Console and CLI accept public keys and opaque backups as string arguments")
        if self.is_cli_compiled():
            cli = node.cli("-rpcwallet=selected")
            assert_equal(cli.dumppqkey(owner_public), owner_record)
            assert_equal(cli.importpqkey(voting_record), {
                "public_key": voting_public, "roles": ["voting"]})
            assert_equal(cli.listpqkeys(), selected.listpqkeys())

        self.restart_node(0)
        if "source" not in node.listwallets():
            node.loadwallet("source")
        source = node.get_wallet_rpc("source")
        assert_equal(self.inventory(source), initial)
        assert_raises_rpc_error(-13, "walletpassphrase", source.dumppqkey, owner_public)
        source.walletpassphrase(passphrase, 120)
        assert_equal(source.dumppqkey(owner_public), owner_record)


if __name__ == "__main__":
    WalletPQKeysTest().main()
