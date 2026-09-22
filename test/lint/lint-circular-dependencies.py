#!/usr/bin/env python3
#
# Copyright (c) 2020-2022 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
#
# Check for circular dependencies

import os
import re
import subprocess
import sys

EXPECTED_CIRCULAR_DEPENDENCIES = (
    "chainparamsbase -> common/args -> chainparamsbase",
    "node/blockstorage -> validation -> node/blockstorage",
    "node/utxo_snapshot -> validation -> node/utxo_snapshot",
    "qt/addresstablemodel -> qt/walletmodel -> qt/addresstablemodel",
    "qt/recentrequeststablemodel -> qt/walletmodel -> qt/recentrequeststablemodel",
    "qt/sendcoinsdialog -> qt/walletmodel -> qt/sendcoinsdialog",
    "qt/transactiontablemodel -> qt/walletmodel -> qt/transactiontablemodel",
    "wallet/wallet -> wallet/walletdb -> wallet/wallet",
    "kernel/coinstats -> validation -> kernel/coinstats",
    "kernel/mempool_persist -> validation -> kernel/mempool_persist",

    # Temporary, removed in followup https://github.com/bitcoin/bitcoin/pull/24230
    # solved
    # "index/base -> node/context -> net_processing -> index/blockfilterindex -> index/base",

    # Syscoin
    "auxpow -> primitives/block -> auxpow",
    "chainparams -> kernel/chainparams -> chainparams",
    "common/args -> logging -> common/args",
    "core_io -> evo/providertx -> core_io",
    "evo/deterministicmns -> evo/providertx -> evo/deterministicmns",
    "evo/deterministicmns -> evo/specialtx -> evo/deterministicmns",
    "evo/deterministicmns -> llmq/quorums_commitment -> evo/deterministicmns",
    "evo/deterministicmns -> node/interface_ui -> evo/deterministicmns",
    "evo/mnauth -> net_processing -> evo/mnauth",
    "evo/specialtx -> llmq/quorums_blockprocessor -> evo/specialtx",
    "evo/specialtx -> validation -> evo/specialtx",
    "governance/governance -> governance/governanceclasses -> governance/governance",
    "governance/governance -> governance/governanceobject -> governance/governance",
    "governance/governance -> masternode/masternodesync -> governance/governance",
    "governance/governance -> net_processing -> governance/governance",
    "init -> masternode/masternodesync -> init",
    "init -> masternode/masternodeutils -> init",
    "llmq/quorums_chainlocks -> net_processing -> llmq/quorums_chainlocks",
    "llmq/quorums_chainlocks -> validation -> llmq/quorums_chainlocks",
    "masternode/masternodepayments -> validation -> masternode/masternodepayments",
    "net -> netmessagemaker -> net",
    "net_processing -> spork -> net_processing",
    "services/nevmconsensus -> validation -> services/nevmconsensus",
    "dsnotificationinterface -> net_processing -> node/blockstorage -> dsnotificationinterface",
    "evo/deterministicmns -> validation -> txmempool -> evo/deterministicmns",
    "evo/providertx -> validation -> txmempool -> evo/providertx",
    "evo/specialtx -> validation -> txmempool -> evo/specialtx",
    "masternode/activemasternode -> validationinterface -> node/blockstorage -> masternode/activemasternode",
    "net_processing -> node/blockstorage -> node/context -> net_processing",
    "nevm/commondata -> nevm/exceptions -> nevm/fixedhash -> nevm/commondata",
    "node/blockstorage -> validation -> validationinterface -> node/blockstorage",
    "net -> rpc/server -> rpc/util -> node/transaction -> net",
    "node/blockstorage -> validation -> zmq/zmqnotificationinterface -> zmq/zmqpublishnotifier -> node/blockstorage",
    "node/transaction -> validation -> zmq/zmqrpc -> rpc/util -> node/transaction",

    # SYSCOIN: The removed BLS/DKG modules exposed alternate shortest paths
    # composed entirely of pre-existing direct include edges.
    "core_io -> services/assetconsensus -> core_io",
    "evo/deterministicmns -> validation -> evo/deterministicmns",
    "governance/governance -> validation -> governance/governance",
    "governance/governanceclasses -> validation -> governance/governanceclasses",
    "llmq/quorums_blockprocessor -> validation -> llmq/quorums_blockprocessor",
    "llmq/quorums_chainlocks -> masternode/masternodesync -> llmq/quorums_chainlocks",
    "masternode/masternodesync -> net -> masternode/masternodesync",
    "masternode/masternodesync -> net_processing -> masternode/masternodesync",
    "masternode/masternodesync -> validation -> masternode/masternodesync",
    "masternode/masternodepayments -> masternode/masternodesync -> net_processing -> masternode/masternodepayments",
    "services/assetconsensus -> validation -> services/assetconsensus",
    "common/bloom -> evo/specialtx -> governance/governance -> common/bloom",
    "core_io -> evo/providertx -> validation -> core_io",
    "evo/deterministicmns -> evo/specialtx -> governance/governance -> evo/deterministicmns",
    "evo/deterministicmns -> evo/providertx -> llmq/quorums_utils -> evo/deterministicmns",
    "evo/deterministicmns -> validationinterface -> node/blockstorage -> evo/deterministicmns",
    "validation -> zmq/zmqnotificationinterface -> zmq/zmqpublishnotifier -> validation",
    "core_io -> evo/specialtx -> governance/governance -> governance/governanceclasses -> core_io",
    "core_io -> evo/specialtx -> governance/governance -> governance/governanceobject -> core_io",
    "core_io -> evo/providertx -> validation -> signet -> core_io",
    "evo/deterministicmns -> evo/specialtx -> governance/governance -> governance/governanceclasses -> evo/deterministicmns",
    "evo/deterministicmns -> evo/specialtx -> governance/governance -> governance/governanceobject -> evo/deterministicmns",
    "evo/deterministicmns -> evo/specialtx -> governance/governance -> masternode/activemasternode -> evo/deterministicmns",
    "evo/deterministicmns -> evo/specialtx -> governance/governance -> masternode/masternodesync -> evo/deterministicmns",
    "evo/deterministicmns -> evo/specialtx -> governance/governance -> net_processing -> evo/deterministicmns",
    "evo/deterministicmns -> validation -> zmq/zmqnotificationinterface -> zmq/zmqpublishnotifier -> evo/deterministicmns",
    "evo/specialtx -> validation -> zmq/zmqnotificationinterface -> zmq/zmqpublishnotifier -> evo/specialtx",
    "llmq/quorums_chainlocks -> validation -> zmq/zmqnotificationinterface -> zmq/zmqpublishnotifier -> llmq/quorums_chainlocks",
    "banman -> common/bloom -> evo/specialtx -> governance/governance -> net_processing -> banman",
    "common/bloom -> evo/specialtx -> governance/governance -> net_processing -> merkleblock -> common/bloom",
    "common/bloom -> evo/specialtx -> governance/governance -> masternode/activemasternode -> net -> common/bloom",
    "core_io -> evo/providertx -> validation -> zmq/zmqrpc -> rpc/util -> core_io",
    "evo/deterministicmns -> evo/specialtx -> governance/governance -> governance/governanceobject -> governance/governancevote -> evo/deterministicmns",
    "evo/deterministicmns -> evo/specialtx -> governance/governance -> masternode/activemasternode -> net -> evo/deterministicmns",
    "banman -> common/bloom -> evo/specialtx -> governance/governance -> masternode/activemasternode -> net -> banman",
    "banman -> common/bloom -> evo/specialtx -> governance/governance -> net_processing -> node/blockstorage -> node/context -> banman",
)

CODE_DIR = "src"


def main():
    circular_dependencies = []
    exit_code = 0

    os.chdir(CODE_DIR)
    files = subprocess.check_output(
        ['git', 'ls-files', '--', '*.h', '*.cpp'],
        text=True,
    ).splitlines()

    command = [sys.executable, "../contrib/devtools/circular-dependencies.py", *files]
    dependencies_output = subprocess.run(
        command,
        stdout=subprocess.PIPE,
        text=True,
    )

    for dependency_str in dependencies_output.stdout.rstrip().split("\n"):
        circular_dependencies.append(
            re.sub("^Circular dependency: ", "", dependency_str)
        )

    # Check for an unexpected dependencies
    for dependency in circular_dependencies:
        if dependency not in EXPECTED_CIRCULAR_DEPENDENCIES:
            exit_code = 1
            print(
                f'A new circular dependency in the form of "{dependency}" appears to have been introduced.\n',
                file=sys.stderr,
            )

    # Check for missing expected dependencies
    for expected_dependency in EXPECTED_CIRCULAR_DEPENDENCIES:
        if expected_dependency not in circular_dependencies:
            exit_code = 1
            print(
                f'Good job! The circular dependency "{expected_dependency}" is no longer present.',
            )
            print(
                f"Please remove it from EXPECTED_CIRCULAR_DEPENDENCIES in {__file__}",
            )
            print(
                "to make sure this circular dependency is not accidentally reintroduced.\n",
            )

    sys.exit(exit_code)


if __name__ == "__main__":
    main()
