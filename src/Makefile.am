# Copyright (c) 2013-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

# SYSCOIN: Legacy BLS and GMP are absent from the post-quantum build graph.
# Pattern rule to print variables, e.g. make print-top_srcdir
print-%: FORCE
	@echo '$*'='$($*)'

DIST_SUBDIRS = secp256k1

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS) $(GPROF_LDFLAGS) $(SANITIZER_LDFLAGS) $(CORE_LDFLAGS)
AM_CXXFLAGS = $(DEBUG_CXXFLAGS) $(HARDENED_CXXFLAGS) $(WARN_CXXFLAGS) $(NOWARN_CXXFLAGS) $(ERROR_CXXFLAGS) $(GPROF_CXXFLAGS) $(SANITIZER_CXXFLAGS) $(CORE_CXXFLAGS)
AM_CPPFLAGS = $(DEBUG_CPPFLAGS) $(HARDENED_CPPFLAGS) $(CORE_CPPFLAGS)
AM_LIBTOOLFLAGS = --preserve-dup-deps
PTHREAD_FLAGS = $(PTHREAD_CFLAGS) $(PTHREAD_LIBS)
EXTRA_LIBRARIES =

lib_LTLIBRARIES =
noinst_LTLIBRARIES =

bin_PROGRAMS =
noinst_PROGRAMS =
check_PROGRAMS =
TESTS =
BENCHMARKS =

# SYSCOIN: The common include and library aliases deliberately omit retired
# Dash BLS, RELIC, mimalloc, and GMP paths.
SYSCOIN_INCLUDES=-I$(builddir) -I$(srcdir)/$(MINISKETCH_INCLUDE_DIR_INT) -I$(srcdir)/secp256k1/include -I$(srcdir)/$(UNIVALUE_INCLUDE_DIR_INT)
SYSCOIN_INCLUDES+=-I$(srcdir)/immer


LIBSYSCOIN_NODE=libsyscoin_node.a
LIBSYSCOIN_COMMON=libsyscoin_common.a
LIBSYSCOIN_CONSENSUS=libsyscoin_consensus.a
LIBSYSCOIN_CLI=libsyscoin_cli.a
LIBSYSCOIN_UTIL=libsyscoin_util.a
LIBSYSCOIN_CRYPTO_BASE=crypto/libsyscoin_crypto_base.la
LIBSYSCOINQT=qt/libsyscoinqt.a
LIBSECP256K1=secp256k1/libsecp256k1.la
LIBNEVM=nevm/libnevm.a
if ENABLE_ZMQ
LIBSYSCOIN_ZMQ=libsyscoin_zmq.a
endif
if BUILD_SYSCOIN_LIBS
LIBSYSCOINCONSENSUS=libsyscoinconsensus.la
endif

if ENABLE_WALLET
LIBSYSCOIN_WALLET=libsyscoin_wallet.a
LIBSYSCOIN_WALLET_TOOL=libsyscoin_wallet_tool.a
endif

LIBSYSCOIN_CRYPTO= $(LIBSYSCOIN_CRYPTO_BASE)
if ENABLE_SSE41
LIBSYSCOIN_CRYPTO_SSE41 = crypto/libsyscoin_crypto_sse41.la
LIBSYSCOIN_CRYPTO += $(LIBSYSCOIN_CRYPTO_SSE41)
endif
if ENABLE_AVX2
LIBSYSCOIN_CRYPTO_AVX2 = crypto/libsyscoin_crypto_avx2.la
LIBSYSCOIN_CRYPTO += $(LIBSYSCOIN_CRYPTO_AVX2)
endif
if ENABLE_X86_SHANI
LIBSYSCOIN_CRYPTO_X86_SHANI = crypto/libsyscoin_crypto_x86_shani.la
LIBSYSCOIN_CRYPTO += $(LIBSYSCOIN_CRYPTO_X86_SHANI)
endif
if ENABLE_ARM_SHANI
LIBSYSCOIN_CRYPTO_ARM_SHANI = crypto/libsyscoin_crypto_arm_shani.la
LIBSYSCOIN_CRYPTO += $(LIBSYSCOIN_CRYPTO_ARM_SHANI)
endif
noinst_LTLIBRARIES += $(LIBSYSCOIN_CRYPTO)

# SYSCOIN: secp256k1 is the only remaining bundled cryptographic subproject.
$(LIBSECP256K1): $(wildcard secp256k1/src/*.h) $(wildcard secp256k1/src/*.c) $(wildcard secp256k1/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

# Make is not made aware of per-object dependencies to avoid limiting building parallelization
# But to build the less dependent modules first, we manually select their order here:
EXTRA_LIBRARIES += \
  $(LIBSYSCOIN_UTIL) \
  $(LIBSYSCOIN_COMMON) \
  $(LIBSYSCOIN_CONSENSUS) \
  $(LIBSYSCOIN_NODE) \
  $(LIBSYSCOIN_CLI) \
  $(LIBSYSCOIN_IPC) \
  $(LIBSYSCOIN_WALLET) \
  $(LIBSYSCOIN_WALLET_TOOL) \
  $(LIBSYSCOIN_ZMQ) \
  $(LIBNEVM)


if BUILD_SYSCOIND
  bin_PROGRAMS += syscoind
endif

if BUILD_SYSCOIN_NODE
  bin_PROGRAMS += syscoin-node
endif

if BUILD_SYSCOIN_CLI
  bin_PROGRAMS += syscoin-cli
endif

if BUILD_SYSCOIN_TX
  bin_PROGRAMS += syscoin-tx
endif

if BUILD_SYSCOIN_UTIL
  bin_PROGRAMS += syscoin-util
endif

if ENABLE_WALLET
if BUILD_SYSCOIN_WALLET
  bin_PROGRAMS += syscoin-wallet
endif
endif

.PHONY: FORCE check-symbols check-security
# SYSCOIN: Fork-owned headers are interleaved with inherited core headers in
# this contiguous manifest.
SYSCOIN_CORE_H = \
  addresstype.h \
  services/nevmconsensus.h \
  services/assetconsensus.h \
  services/rpc/assetrpc.h \
  spork.h \
  dsnotificationinterface.h \
  governance/governance.h \
  governance/governanceclasses.h \
  governance/governancecommon.h \
  governance/governanceexceptions.h \
  governance/governanceobject.h \
  governance/governancepages.h \
  governance/pq_governance_auth.h \
  governance/pq_governance_auth_interface.h \
  governance/governancevalidators.h \
  governance/governancevote.h \
  governance/governancevotedb.h \
  cxxtimer.hpp \
  evo/deterministicmns.h \
  evo/evodb.h \
  evo/mnauth.h \
  evo/mnauth_types.h \
  evo/dmnstate.h \
  evo/providertx.h \
  evo/pq_registry.h \
  evo/specialtx_payload.h \
  evo/specialtx.h \
  masternode/activemasternode.h \
  masternode/pq_operatorkeys.h \
  masternode/masternodemeta.h \
  masternode/masternodepayments.h \
  masternode/masternodesync.h \
  masternode/masternodeutils.h \
  flatdatabase.h \
  messagesigner.h \
  netfulfilledman.h \
  cachemap.h \
  cachemultimap.h \
  addrdb.h \
  addrman.h \
  addrman_impl.h \
  attributes.h \
  auxpow.h \
  banman.h \
  base58.h \
  batchedlogger.h \
  bech32.h \
  bip324.h \
  blockencodings.h \
  blockfilter.h \
  chain.h \
  chainparams.h \
  chainparamsbase.h \
  chainparamsseeds.h \
  checkqueue.h \
  clientversion.h \
  coins.h \
  common/args.h \
  common/bloom.h \
  common/init.h \
  common/run_command.h \
  common/url.h \
  compat/assumptions.h \
  compat/byteswap.h \
  compat/compat.h \
  compat/cpuid.h \
  compat/endian.h \
  common/settings.h \
  common/system.h \
  node/connection_types.h \
  consensus/consensus.h \
  consensus/pq_migration_config.h \
  consensus/pq_migration.h \
  consensus/tx_check.h \
  consensus/tx_verify.h \
  crypto/legacy_bls.h \
  core_io.h \
  core_memusage.h \
  cuckoocache.h \
  dbwrapper.h \
  deploymentinfo.h \
  deploymentstatus.h \
  node/eviction.h \
  external_signer.h \
  flatfile.h \
  ctpl_stl.h \
  headerssync.h \
  httprpc.h \
  httpserver.h \
  i2p.h \
  index/base.h \
  index/blockfilterindex.h \
  index/coinstatsindex.h \
  index/disktxpos.h \
  index/txindex.h \
  indirectmap.h \
  init.h \
  init/common.h \
  interfaces/chain.h \
  interfaces/echo.h \
  interfaces/handler.h \
  interfaces/init.h \
  interfaces/ipc.h \
  interfaces/node.h \
  interfaces/wallet.h \
  kernel/blockmanager_opts.h \
  kernel/chain.h \
  kernel/chainparams.h \
  kernel/chainstatemanager_opts.h \
  kernel/checks.h \
  kernel/coinstats.h \
  kernel/context.h \
  kernel/cs_main.h \
  kernel/disconnected_transactions.h \
  kernel/mempool_entry.h \
  kernel/mempool_limits.h \
  kernel/mempool_options.h \
  kernel/mempool_persist.h \
  kernel/mempool_removal_reason.h \
  kernel/messagestartchars.h \
  kernel/notifications_interface.h \
  kernel/validation_cache_sizes.h \
  key.h \
  key_io.h \
  llmq/quorums_blockprocessor.h \
  llmq/quorums_commitment.h \
  llmq/quorums_chainlocks.h \
  llmq/quorums_init.h \
  llmq/quorums_utils.h \
  logging.h \
  logging/timer.h \
  mapport.h \
  node/mempool_args.h \
  memusage.h \
  merkleblock.h \
  net.h \
  net_permissions.h \
  net_processing.h \
  net_types.h \
  netaddress.h \
  netbase.h \
  netgroup.h \
  netmessagemaker.h \
  node/abort.h \
  node/blockmanager_args.h \
  node/blockstorage.h \
  node/btcheader_state.h \
  node/caches.h \
  node/chainstate.h \
  node/chainstatemanager_args.h \
  node/coin.h \
  node/coins_view_args.h \
  node/connection_types.h \
  node/context.h \
  node/database_args.h \
  node/eviction.h \
  node/interface_ui.h \
  node/kernel_notifications.h \
  node/mempool_args.h \
  node/mempool_persist_args.h \
  node/miner.h \
  node/mini_miner.h \
  node/minisketchwrapper.h \
  node/peerman_args.h \
  node/psbt.h \
  node/transaction.h \
  node/interface_ui.h \
  node/txreconciliation.h \
  node/utxo_snapshot.h \
  node/validation_cache_args.h \
  noui.h \
  outputtype.h \
  policy/feerate.h \
  policy/fees.h \
  policy/fees_args.h \
  policy/packages.h \
  policy/policy.h \
  policy/rbf.h \
  policy/settings.h \
  pow.h \
  protocol.h \
  psbt.h \
  random.h \
  randomenv.h \
  rest.h \
  reverse_iterator.h \
  rpc/blockchain.h \
  rpc/auxpow_miner.h \
  rpc/client.h \
  rpc/mempool.h \
  rpc/mining.h \
  rpc/protocol.h \
  rpc/rawtransaction_util.h \
  rpc/register.h \
  rpc/request.h \
  rpc/server.h \
  rpc/server_util.h \
  rpc/util.h \
  saltedhasher.h \
  scheduler.h \
  script/descriptor.h \
  script/keyorigin.h \
  script/miniscript.h \
  script/sigcache.h \
  script/sign.h \
  script/signingprovider.h \
  script/solver.h \
  shutdown.h \
  signet.h \
  streams.h \
  support/allocators/pool.h \
  support/allocators/secure.h \
  support/allocators/zeroafterfree.h \
  support/allocators/pooled_secure.h \
  support/allocators/mt_pooled_secure.h \
  support/cleanse.h \
  support/events.h \
  support/lockedpool.h \
  sync.h \
  threadsafety.h \
  timedata.h \
  torcontrol.h \
  txdb.h \
  txmempool.h \
  txorphanage.h \
  txrequest.h \
  undo.h \
  unordered_lru_cache.h \
  util/any.h \
  util/asmap.h \
  util/batchpriority.h \
  util/bip32.h \
  util/bitdeque.h \
  util/bytevectorhash.h \
  util/chaintype.h \
  util/check.h \
  util/epochguard.h \
  util/error.h \
  util/exception.h \
  util/fastrange.h \
  util/fees.h \
  util/fs.h \
  util/fs_helpers.h \
  util/golombrice.h \
  util/hash_type.h \
  util/hasher.h \
  util/insert.h \
  util/macros.h \
  util/message.h \
  util/moneystr.h \
  util/overflow.h \
  util/overloaded.h \
  util/rbf.h \
  util/readwritefile.h \
  util/ranges.h \
  util/result.h \
  util/serfloat.h \
  util/signalinterrupt.h \
  util/sock.h \
  util/spanparsing.h \
  util/string.h \
  util/syserror.h \
  util/thread.h \
  util/threadinterrupt.h \
  util/threadnames.h \
  util/time.h \
  util/tokenpipe.h \
  util/trace.h \
  util/translation.h \
  util/types.h \
  util/ui_change_type.h \
  util/vector.h \
  validation.h \
  validationinterface.h \
  versionbits.h \
  wallet/bdb.h \
  wallet/coincontrol.h \
  wallet/coinselection.h \
  wallet/context.h \
  wallet/crypter.h \
  wallet/db.h \
  wallet/dump.h \
  wallet/external_signer_scriptpubkeyman.h \
  wallet/feebumper.h \
  wallet/fees.h \
  wallet/load.h \
  wallet/receive.h \
  wallet/rpc/util.h \
  wallet/rpc/wallet.h \
  wallet/rpc/spend.h \
  wallet/salvage.h \
  wallet/scriptpubkeyman.h \
  wallet/spend.h \
  wallet/sqlite.h \
  wallet/transaction.h \
  wallet/types.h \
  wallet/wallet.h \
  wallet/walletdb.h \
  wallet/wallettool.h \
  wallet/walletutil.h \
  walletinitinterface.h \
  warnings.h \
  zmq/zmqabstractnotifier.h \
  zmq/zmqnotificationinterface.h \
  zmq/zmqpublishnotifier.h \
  zmq/zmqrpc.h \
  zmq/zmqutil.h


obj/build.h: FORCE
	@$(MKDIR_P) $(builddir)/obj
	$(AM_V_GEN) $(top_srcdir)/share/genbuild.sh "$(abs_top_builddir)/src/obj/build.h" \
	  "$(abs_top_srcdir)"

libsyscoin_util_a-clientversion.$(OBJEXT): obj/build.h


 # nevm
 nevm_libnevm_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES)
 nevm_libnevm_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
 nevm_libnevm_a_SOURCES = \
  nevm/address.cpp \
  nevm/address.h \
  nevm/common.cpp \
  nevm/common.h \
  nevm/commondata.cpp \
  nevm/commondata.h \
  nevm/exceptions.h \
  nevm/fixedhash.cpp \
  nevm/fixedhash.h \
  nevm/rlp.cpp \
  nevm/rlp.h \
  nevm/sha3.cpp \
  nevm/sha3.h \
  nevm/nevm.cpp \
  nevm/nevm.h \
  nevm/vector_ref.h



# SYSCOIN: Fork-owned services are interleaved with inherited node sources in
# this contiguous archive manifest.
libsyscoin_node_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES) $(LEVELDB_CPPFLAGS) $(BOOST_CPPFLAGS) $(MINIUPNPC_CPPFLAGS) $(NATPMP_CPPFLAGS) $(EVENT_CFLAGS) $(EVENT_PTHREADS_CFLAGS)
libsyscoin_node_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsyscoin_node_a_SOURCES = \
  services/nevmconsensus.cpp \
  services/rpc/nevmrpc.cpp \
  services/assetconsensus.cpp \
  services/rpc/assetrpc.cpp \
  core_write.cpp \
  dsnotificationinterface.cpp \
  governance/governance.cpp \
  governance/governanceclasses.cpp \
  governance/governancecommon.cpp \
  governance/governanceobject.cpp \
  governance/pq_governance_auth.cpp \
  governance/governanceexceptions.cpp \
  governance/governancevalidators.cpp \
  governance/governancevote.cpp \
  governance/governancevotedb.cpp \
  evo/deterministicmns.cpp \
  evo/mnauth.cpp \
  evo/dmnstate.cpp \
  evo/provider_revoke_payload.h \
  evo/providertx.cpp \
  evo/pq_providertx.cpp \
  evo/pq_providertx.h \
  evo/pq_payment_probation.cpp \
  evo/pq_payment_probation.h \
  evo/pq_payment_probation_db.cpp \
  evo/pq_payment_probation_db.h \
  evo/pq_registry.cpp \
  evo/pq_registry.h \
  evo/specialtx.cpp \
  llmq/quorums_blockprocessor.cpp \
  llmq/quorums_commitment.cpp \
  llmq/quorums_chainlocks.cpp \
  llmq/quorums_init.cpp \
  llmq/quorums_utils.cpp \
  llmq/legacy_quorum_commitment.cpp \
  llmq/legacy_quorum_commitment.h \
  llmq/btc_header_policy.cpp \
  llmq/btc_header_policy.h \
  llmq/pq_chainlock_types.cpp \
  llmq/pq_chainlock_types.h \
  llmq/pq_chainlock_collector.cpp \
  llmq/pq_chainlock_collector.h \
  llmq/pq_chainlock_persistence.cpp \
  llmq/pq_chainlock_persistence.h \
  llmq/pq_chainlock_test_fixture.cpp \
  llmq/pq_chainlock_test_fixture.h \
  llmq/pq_btcc.cpp \
  llmq/pq_btcc.h \
  llmq/pq_payment_audit.cpp \
  llmq/pq_payment_audit.h \
  llmq/pq_payment_audit_collector.cpp \
  llmq/pq_payment_audit_collector.h \
  llmq/pq_payment_audit_signer.cpp \
  llmq/pq_payment_audit_signer.h \
  llmq/pq_payment_audit_staging_store.cpp \
  llmq/pq_payment_audit_staging_store.h \
  llmq/pq_payment_audit_store.cpp \
  llmq/pq_payment_audit_store.h \
  llmq/pq_payment_audit_verify.cpp \
  llmq/pq_payment_audit_verify.h \
  llmq/pq_chainlock_schedule.cpp \
  llmq/pq_chainlock_schedule.h \
  llmq/pq_chainlock_store.cpp \
  llmq/pq_chainlock_store.h \
  llmq/pq_child_key_derivation.h \
  llmq/pq_child_key_tree.cpp \
  llmq/pq_child_key_tree.h \
  llmq/pq_chainlock_signer.cpp \
  llmq/pq_chainlock_signer.h \
  llmq/pq_chainlock_verify.cpp \
  llmq/pq_chainlock_verify.h \
  llmq/pq_global_auth.cpp \
  llmq/pq_global_auth.h \
  llmq/pq_mnauth.cpp \
  llmq/pq_mnauth.h \
  llmq/pq_operator_key_state.cpp \
  llmq/pq_operator_key_state.h \
  llmq/pq_quorum_builder.cpp \
  llmq/pq_quorum_builder.h \
  llmq/pq_quorum_overlay.cpp \
  llmq/pq_quorum_overlay.h \
  llmq/pq_signer_journal.cpp \
  llmq/pq_signer_journal.h \
  masternode/activemasternode.cpp \
  masternode/pq_operatorkeys.cpp \
  masternode/pq_operatorkeys.h \
  masternode/masternodemeta.cpp \
  masternode/masternodepayments.cpp \
  masternode/masternodesync.cpp \
  masternode/masternodeutils.cpp \
  messagesigner.cpp \
  spork.cpp \
  addrdb.cpp \
  addrman.cpp \
  batchedlogger.cpp \
  banman.cpp \
  bip324.cpp \
  blockencodings.cpp \
  blockfilter.cpp \
  chain.cpp \
  consensus/tx_verify.cpp \
  dbwrapper.cpp \
  deploymentstatus.cpp \
  flatfile.cpp \
  headerssync.cpp \
  httprpc.cpp \
  httpserver.cpp \
  i2p.cpp \
  index/base.cpp \
  index/blockfilterindex.cpp \
  index/coinstatsindex.cpp \
  index/txindex.cpp \
  init.cpp \
  kernel/chain.cpp \
  kernel/checks.cpp \
  kernel/coinstats.cpp \
  kernel/context.cpp \
  kernel/cs_main.cpp \
  kernel/mempool_persist.cpp \
  kernel/mempool_removal_reason.cpp \
  mapport.cpp \
  net.cpp \
  netfulfilledman.cpp \
  netgroup.cpp \
  net_processing.cpp \
  node/abort.cpp \
  node/blockmanager_args.cpp \
  node/blockstorage.cpp \
  node/caches.cpp \
  node/chainstate.cpp \
  node/chainstatemanager_args.cpp \
  node/coin.cpp \
  node/coins_view_args.cpp \
  node/connection_types.cpp \
  node/context.cpp \
  node/database_args.cpp \
  node/eviction.cpp \
  node/interfaces.cpp \
  node/kernel_notifications.cpp \
  node/mempool_args.cpp \
  node/mempool_persist_args.cpp \
  node/miner.cpp \
  node/mini_miner.cpp \
  node/minisketchwrapper.cpp \
  node/peerman_args.cpp \
  node/psbt.cpp \
  node/transaction.cpp \
  node/interface_ui.cpp \
  node/txreconciliation.cpp \
  node/utxo_snapshot.cpp \
  node/validation_cache_args.cpp \
  noui.cpp \
  policy/fees.cpp \
  policy/fees_args.cpp \
  policy/packages.cpp \
  policy/rbf.cpp \
  policy/settings.cpp \
  primitives/transaction.cpp \
  pow.cpp \
  rest.cpp \
  rpc/auxpow_miner.cpp \
  rpc/blockchain.cpp \
  rpc/fees.cpp \
  rpc/mempool.cpp \
  rpc/mining.cpp \
  rpc/node.cpp \
  rpc/net.cpp \
  rpc/output_script.cpp \
  rpc/rawtransaction.cpp \
  rpc/server.cpp \
  rpc/masternode.cpp \
  rpc/governance.cpp \
  rpc/rpcevo.cpp \
  rpc/rpcquorums.cpp \
  rpc/server_util.cpp \
  rpc/signmessage.cpp \
  rpc/txoutproof.cpp \
  script/sigcache.cpp \
  shutdown.cpp \
  signet.cpp \
  timedata.cpp \
  torcontrol.cpp \
  txdb.cpp \
  txmempool.cpp \
  txorphanage.cpp \
  txrequest.cpp \
  validation.cpp \
  validationinterface.cpp \
  versionbits.cpp \
  $(SYSCOIN_CORE_H)

if ENABLE_WALLET
libsyscoin_node_a_SOURCES += wallet/init.cpp
libsyscoin_node_a_CPPFLAGS += $(BDB_CPPFLAGS)
endif
if !ENABLE_WALLET
libsyscoin_node_a_SOURCES += dummywallet.cpp
endif
#

# zmq #
if ENABLE_ZMQ
libsyscoin_zmq_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES) $(ZMQ_CFLAGS)
libsyscoin_zmq_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsyscoin_zmq_a_SOURCES = \
  zmq/zmqabstractnotifier.cpp \
  zmq/zmqnotificationinterface.cpp \
  zmq/zmqpublishnotifier.cpp \
  zmq/zmqrpc.cpp \
  zmq/zmqutil.cpp
endif
#


# wallet #
libsyscoin_wallet_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES) $(BOOST_CPPFLAGS) $(BDB_CPPFLAGS) $(SQLITE_CFLAGS)
libsyscoin_wallet_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsyscoin_wallet_a_SOURCES = \
  wallet/coincontrol.cpp \
  wallet/context.cpp \
  wallet/crypter.cpp \
  wallet/db.cpp \
  wallet/dump.cpp \
  wallet/external_signer_scriptpubkeyman.cpp \
  wallet/feebumper.cpp \
  wallet/fees.cpp \
  wallet/interfaces.cpp \
  wallet/load.cpp \
  wallet/receive.cpp \
  wallet/rpc/addresses.cpp \
  wallet/rpc/backup.cpp \
  wallet/rpc/coins.cpp \
  wallet/rpc/encrypt.cpp \
  wallet/rpc/spend.cpp \
  wallet/rpc/signmessage.cpp \
  wallet/rpc/transactions.cpp \
  wallet/rpc/util.cpp \
  wallet/rpc/wallet.cpp \
  wallet/scriptpubkeyman.cpp \
  wallet/spend.cpp \
  wallet/transaction.cpp \
  wallet/wallet.cpp \
  wallet/walletdb.cpp \
  wallet/walletutil.cpp \
  wallet/coinselection.cpp \
  rpc/governance.cpp \
  rpc/rawtransaction.cpp \
  rpc/rpcevo.cpp \
  rpc/masternode.cpp \
  rpc/auxpow_miner.cpp \
  services/rpc/wallet/nevmwalletrpc.cpp \
  wallet/rpcevo.cpp \
  wallet/rpcgovernance.cpp \
  wallet/rpcmasternode.cpp \
  $(SYSCOIN_CORE_H)

if USE_SQLITE
libsyscoin_wallet_a_SOURCES += wallet/sqlite.cpp
endif
if USE_BDB
libsyscoin_wallet_a_SOURCES += wallet/bdb.cpp wallet/salvage.cpp
endif
#

# wallet tool #
libsyscoin_wallet_tool_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES) $(BOOST_CPPFLAGS)
libsyscoin_wallet_tool_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsyscoin_wallet_tool_a_SOURCES = \
  wallet/wallettool.cpp \
  $(SYSCOIN_CORE_H)

# crypto #
crypto_libsyscoin_crypto_base_la_CPPFLAGS = $(AM_CPPFLAGS)

# Specify -static in both CXXFLAGS and LDFLAGS so libtool will only build a
# static version of this library. We don't need a dynamic version, and a dynamic
# version can't be used on windows anyway because the library doesn't currently
# export DLL symbols.
crypto_libsyscoin_crypto_base_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libsyscoin_crypto_base_la_LDFLAGS = $(AM_LDFLAGS) -static

# SYSCOIN: Fork-only SLH-DSA and SPHINCS/C11 sources are grouped at the tail
# of this contiguous list because the MSVC project generator consumes it whole.
crypto_libsyscoin_crypto_base_la_SOURCES = \
  crypto/aes.cpp \
  crypto/aes.h \
  crypto/chacha20.h \
  crypto/chacha20.cpp \
  crypto/chacha20poly1305.h \
  crypto/chacha20poly1305.cpp \
  crypto/common.h \
  crypto/hkdf_sha256_32.cpp \
  crypto/hkdf_sha256_32.h \
  crypto/hmac_sha256.cpp \
  crypto/hmac_sha256.h \
  crypto/hmac_sha512.cpp \
  crypto/hmac_sha512.h \
  crypto/poly1305.h \
  crypto/poly1305.cpp \
  crypto/muhash.h \
  crypto/muhash.cpp \
  crypto/ripemd160.cpp \
  crypto/ripemd160.h \
  crypto/sha1.cpp \
  crypto/sha1.h \
  crypto/sha256.cpp \
  crypto/sha256.h \
  crypto/sha3.cpp \
  crypto/sha3.h \
  crypto/sha512.cpp \
  crypto/sha512.h \
  crypto/siphash.cpp \
  crypto/siphash.h \
  crypto/slhdsa/secure.cpp \
  crypto/slhdsa/secure.h \
  crypto/slhdsa/selftest.cpp \
  crypto/slhdsa/selftest.h \
  crypto/slhdsa/slhdsa.cpp \
  crypto/slhdsa/slhdsa.h \
  crypto/slhdsa/vendor/cbmc.h \
  crypto/slhdsa/vendor/plat_local.h \
  crypto/slhdsa/vendor/sha3_api.c \
  crypto/slhdsa/vendor/sha3_api.h \
  crypto/slhdsa/vendor/sha3_f1600.c \
  crypto/slhdsa/vendor/slh_adrs.h \
  crypto/slhdsa/vendor/slh_dsa.c \
  crypto/slhdsa/vendor/slh_dsa.h \
  crypto/slhdsa/vendor/slh_param.h \
  crypto/slhdsa/vendor/slh_shake.c \
  crypto/slhdsa/vendor/slh_sys.h \
  crypto/slhdsa/vendor/slh_var.h \
  crypto/sphincs_c11/sphincs_c11.cpp \
  crypto/sphincs_c11/sphincs_c11.h

if USE_ASM
crypto_libsyscoin_crypto_base_la_SOURCES += crypto/sha256_sse4.cpp
endif

# See explanation for -static in crypto_libsyscoin_crypto_base_la's LDFLAGS and
# CXXFLAGS above
crypto_libsyscoin_crypto_sse41_la_LDFLAGS = $(AM_LDFLAGS) -static
crypto_libsyscoin_crypto_sse41_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libsyscoin_crypto_sse41_la_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libsyscoin_crypto_sse41_la_CXXFLAGS += $(SSE41_CXXFLAGS)
crypto_libsyscoin_crypto_sse41_la_CPPFLAGS += -DENABLE_SSE41
crypto_libsyscoin_crypto_sse41_la_SOURCES = crypto/sha256_sse41.cpp

# See explanation for -static in crypto_libsyscoin_crypto_base_la's LDFLAGS and
# CXXFLAGS above
crypto_libsyscoin_crypto_avx2_la_LDFLAGS = $(AM_LDFLAGS) -static
crypto_libsyscoin_crypto_avx2_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libsyscoin_crypto_avx2_la_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libsyscoin_crypto_avx2_la_CXXFLAGS += $(AVX2_CXXFLAGS)
crypto_libsyscoin_crypto_avx2_la_CPPFLAGS += -DENABLE_AVX2
crypto_libsyscoin_crypto_avx2_la_SOURCES = crypto/sha256_avx2.cpp

# See explanation for -static in crypto_libsyscoin_crypto_base_la's LDFLAGS and
# CXXFLAGS above
crypto_libsyscoin_crypto_x86_shani_la_LDFLAGS = $(AM_LDFLAGS) -static
crypto_libsyscoin_crypto_x86_shani_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libsyscoin_crypto_x86_shani_la_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libsyscoin_crypto_x86_shani_la_CXXFLAGS += $(X86_SHANI_CXXFLAGS)
crypto_libsyscoin_crypto_x86_shani_la_CPPFLAGS += -DENABLE_X86_SHANI
crypto_libsyscoin_crypto_x86_shani_la_SOURCES = crypto/sha256_x86_shani.cpp

# See explanation for -static in crypto_libsyscoin_crypto_base_la's LDFLAGS and
# CXXFLAGS above
crypto_libsyscoin_crypto_arm_shani_la_LDFLAGS = $(AM_LDFLAGS) -static
crypto_libsyscoin_crypto_arm_shani_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) -static
crypto_libsyscoin_crypto_arm_shani_la_CPPFLAGS = $(AM_CPPFLAGS)
crypto_libsyscoin_crypto_arm_shani_la_CXXFLAGS += $(ARM_SHANI_CXXFLAGS)
crypto_libsyscoin_crypto_arm_shani_la_CPPFLAGS += -DENABLE_ARM_SHANI
crypto_libsyscoin_crypto_arm_shani_la_SOURCES = crypto/sha256_arm_shani.cpp

# consensus #
# SYSCOIN: Historical BLS is opaque replay data, not linked consensus code.
libsyscoin_consensus_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES)
libsyscoin_consensus_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsyscoin_consensus_a_SOURCES = \
  arith_uint256.cpp \
  arith_uint256.h \
  consensus/amount.h \
  consensus/merkle.cpp \
  consensus/merkle.h \
  consensus/params.h \
  consensus/tx_check.cpp \
  consensus/validation.h \
  hash.cpp \
  hash.h \
  prevector.h \
  primitives/block.cpp \
  primitives/block.h \
  primitives/pureheader.cpp \
  primitives/pureheader.h \
  primitives/transaction.cpp \
  primitives/transaction.h \
  pubkey.cpp \
  pubkey.h \
  script/syscoinconsensus.cpp \
  script/interpreter.cpp \
  script/interpreter.h \
  script/script.cpp \
  script/script.h \
  script/script_error.cpp \
  script/script_error.h \
  serialize.h \
  span.h \
  tinyformat.h \
  uint256.cpp \
  uint256.h \
  util/strencodings.cpp \
  util/strencodings.h \
  version.h
#

# common #
libsyscoin_common_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES) $(LEVELDB_CPPFLAGS)  $(BOOST_CPPFLAGS)
libsyscoin_common_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsyscoin_common_a_SOURCES = \
  addresstype.cpp \
  services/nevmconsensus.cpp \
  services/assetconsensus.cpp \
  auxpow.cpp \
  base58.cpp \
  bech32.cpp \
  chainparams.cpp \
  coins.cpp \
  common/args.cpp \
  common/bloom.cpp \
  common/config.cpp \
  common/init.cpp \
  common/interfaces.cpp \
  common/run_command.cpp \
  common/settings.cpp \
  common/system.cpp \
  core_read.cpp \
  core_write.cpp \
  dbwrapper.cpp \
  deploymentinfo.cpp \
  external_signer.cpp \
  init/common.cpp \
  kernel/chainparams.cpp \
  key.cpp \
  key_io.cpp \
  llmq/quorums_chainlocks.cpp \
  merkleblock.cpp \
  messagesigner.cpp \
  net_types.cpp \
  netaddress.cpp \
  netbase.cpp \
  net_permissions.cpp \
  outputtype.cpp \
  policy/feerate.cpp \
  policy/policy.cpp \
  protocol.cpp \
  saltedhasher.cpp \
  psbt.cpp \
  rpc/external_signer.cpp \
  rpc/rawtransaction_util.cpp \
  rpc/request.cpp \
  rpc/util.cpp \
  scheduler.cpp \
  script/descriptor.cpp \
  script/miniscript.cpp \
  script/sign.cpp \
  script/signingprovider.cpp \
  script/solver.cpp \
  sync.cpp \
  warnings.cpp \
  $(SYSCOIN_CORE_H)

if USE_LIBEVENT
libsyscoin_common_a_CPPFLAGS += $(EVENT_CFLAGS)
libsyscoin_common_a_SOURCES += common/url.cpp
endif
#

# util #
# SYSCOIN: Live BLS verification and worker utilities are retired.
libsyscoin_util_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES)
libsyscoin_util_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsyscoin_util_a_SOURCES = \
  support/lockedpool.cpp \
  chainparamsbase.cpp \
  clientversion.cpp \
  logging.cpp \
  random.cpp \
  randomenv.cpp \
  streams.cpp \
  support/cleanse.cpp \
  sync.cpp \
  util/asmap.cpp \
  util/batchpriority.cpp \
  util/bip32.cpp \
  util/bytevectorhash.cpp \
  util/chaintype.cpp \
  util/check.cpp \
  util/error.cpp \
  util/exception.cpp \
  util/fees.cpp \
  util/fs.cpp \
  util/fs_helpers.cpp \
  util/hasher.cpp \
  util/sock.cpp \
  util/syserror.cpp \
  util/message.cpp \
  util/moneystr.cpp \
  util/rbf.cpp \
  util/readwritefile.cpp \
  util/signalinterrupt.cpp \
  util/thread.cpp \
  util/threadinterrupt.cpp \
  util/threadnames.cpp \
  util/serfloat.cpp \
  util/spanparsing.cpp \
  util/strencodings.cpp \
  util/string.cpp \
  util/time.cpp \
  util/tokenpipe.cpp \
  $(SYSCOIN_CORE_H)
#

# cli #
libsyscoin_cli_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES)
libsyscoin_cli_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
libsyscoin_cli_a_SOURCES = \
  compat/stdin.h \
  compat/stdin.cpp \
  rpc/client.cpp \
  $(SYSCOIN_CORE_H)

nodist_libsyscoin_util_a_SOURCES = $(srcdir)/obj/build.h
#

# syscoind & syscoin-node binaries #
syscoin_daemon_sources = syscoind.cpp
syscoin_bin_cppflags = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES)
syscoin_bin_cxxflags = $(AM_CXXFLAGS) $(PIE_FLAGS)
syscoin_bin_ldflags = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
syscoin_daemon_sources += syscoind-res.rc
endif
# SYSCOIN need getauxwork and mempool stuff inside of wallet so server needs linking here for now but order has to be after wallet
# SYSCOIN: Node binaries link PQ crypto without the retired BLS/GMP closure.
syscoin_bin_ldadd = \
  $(LIBSYSCOIN_WALLET) \
  $(LIBSYSCOIN_NODE) \
  $(LIBSYSCOIN_COMMON) \
  $(LIBSYSCOIN_UTIL) \
  $(LIBUNIVALUE) \
  $(LIBSYSCOIN_ZMQ) \
  $(LIBSYSCOIN_CONSENSUS) \
  $(LIBSYSCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBNEVM)

syscoin_bin_ldadd += $(BDB_LIBS) $(MINIUPNPC_LIBS) $(NATPMP_LIBS) $(EVENT_PTHREADS_LIBS) $(EVENT_LIBS) $(ZMQ_LIBS) $(SQLITE_LIBS)

syscoind_SOURCES = $(syscoin_daemon_sources) init/syscoind.cpp
syscoind_CPPFLAGS = $(syscoin_bin_cppflags)
syscoind_CXXFLAGS = $(syscoin_bin_cxxflags)
syscoind_LDFLAGS = $(syscoin_bin_ldflags)
syscoind_LDADD = $(syscoin_bin_ldadd)

syscoin_node_SOURCES = $(syscoin_daemon_sources) init/syscoin-node.cpp
syscoin_node_CPPFLAGS = $(syscoin_bin_cppflags)
syscoin_node_CXXFLAGS = $(syscoin_bin_cxxflags)
syscoin_node_LDFLAGS = $(syscoin_bin_ldflags)
syscoin_node_LDADD = $(syscoin_bin_ldadd) $(LIBSYSCOIN_IPC) $(LIBMULTIPROCESS_LIBS)

# syscoin-cli binary #
syscoin_cli_SOURCES = syscoin-cli.cpp
syscoin_cli_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES) $(EVENT_CFLAGS)
syscoin_cli_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
syscoin_cli_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
syscoin_cli_SOURCES += syscoin-cli-res.rc
endif


# SYSCOIN: The CLI has no legacy BLS runtime dependency.
syscoin_cli_LDADD = \
  $(LIBSYSCOIN_CLI) \
  $(LIBUNIVALUE) \
  $(LIBSYSCOIN_COMMON) \
  $(LIBSYSCOIN_UTIL) \
  $(LIBSYSCOIN_CRYPTO)

syscoin_cli_LDADD += $(EVENT_LIBS)
#

# syscoin-tx binary #
syscoin_tx_SOURCES = syscoin-tx.cpp
syscoin_tx_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES)
syscoin_tx_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
syscoin_tx_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
syscoin_tx_SOURCES += syscoin-tx-res.rc
endif

# SYSCOIN: Offline transaction tooling uses the BLS-free consensus closure.
syscoin_tx_LDADD = \
  $(LIBUNIVALUE) \
  $(LIBSYSCOIN_COMMON) \
  $(LIBSYSCOIN_UTIL) \
  $(LIBSYSCOIN_CONSENSUS) \
  $(LIBSYSCOIN_CRYPTO) \
  $(LIBLEVELDB) \
  $(LIBMEMENV) \
  $(LIBSECP256K1) \
  $(LIBNEVM)
#

# syscoin-util binary #
syscoin_util_SOURCES = syscoin-util.cpp
syscoin_util_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES)
syscoin_util_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)
syscoin_util_LDFLAGS = $(RELDFLAGS) $(AM_LDFLAGS) $(LIBTOOL_APP_LDFLAGS) $(PTHREAD_FLAGS)

if TARGET_WINDOWS
syscoin_util_SOURCES += syscoin-util-res.rc
endif

# SYSCOIN: Utility binaries use the BLS-free consensus closure.
syscoin_util_LDADD = \
  $(LIBSYSCOIN_COMMON) \
  $(LIBSYSCOIN_UTIL) \
  $(LIBSYSCOIN_CONSENSUS) \
  $(LIBSYSCOIN_CRYPTO) \
  $(LIBSECP256K1) \
  $(LIBNEVM) \
  $(LIBUNIVALUE)
#

# syscoin-wallet binary #
syscoin_wallet_SOURCES = syscoin-wallet.cpp
syscoin_wallet_SOURCES += init/syscoin-wallet.cpp
syscoin_wallet_CPPFLAGS = $(syscoin_bin_cppflags)
syscoin_wallet_CXXFLAGS = $(syscoin_bin_cxxflags)
syscoin_wallet_LDFLAGS = $(syscoin_bin_ldflags)
syscoin_wallet_LDADD = $(LIBSYSCOIN_WALLET_TOOL) $(syscoin_bin_ldadd)

if TARGET_WINDOWS
syscoin_wallet_SOURCES += syscoin-wallet-res.rc
endif
#

# syscoinconsensus library #
if BUILD_SYSCOIN_LIBS
lib_LTLIBRARIES += $(LIBSYSCOINCONSENSUS)

include_HEADERS = script/syscoinconsensus.h
# SYSCOIN: The public script-verification library has no PQ API. Keep its
# crypto closure explicit so node-only algorithms cannot become exported
# dependencies merely by being added to libsyscoin_crypto_base.
libsyscoinconsensus_la_SOURCES = \
  support/cleanse.cpp \
  crypto/hmac_sha512.cpp \
  crypto/ripemd160.cpp \
  crypto/sha1.cpp \
  crypto/sha256.cpp \
  crypto/sha512.cpp \
  $(libsyscoin_consensus_a_SOURCES)

if USE_ASM
libsyscoinconsensus_la_SOURCES += crypto/sha256_sse4.cpp
endif


libsyscoinconsensus_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libsyscoinconsensus_la_LIBADD = $(LIBSECP256K1)
libsyscoinconsensus_la_CPPFLAGS = $(AM_CPPFLAGS) -I$(builddir)/obj -I$(srcdir)/secp256k1/include -DBUILD_SYSCOIN_INTERNAL
libsyscoinconsensus_la_CPPFLAGS += -I$(srcdir)/immer
libsyscoinconsensus_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

endif

#
# syscoin pre-built binaries #
dist_bin_SCRIPTS =
nodist_bin_SCRIPTS =
# SYSCOIN: Package the managed Bitcoin-header helper and its license.
btcheadernodedocdir = $(docdir)/btcheadernode
nodist_btcheadernodedoc_DATA =
if TARGET_X86_64_LINUX
dist_bin_SCRIPTS += bin/linux/x86_64/sysgeth
endif
# SYSCOIN: release builds enable this helper on every supported Linux/macOS
# architecture. Developer builds retain an explicit configure opt-out.
if ENABLE_BTCHEADERNODE_BUILD
BTCHEADERNODE_BIN_STAMP = bin/btcheadernode/.build-stamp
nodist_bin_SCRIPTS += \
  bin/btcheadernode/bin/bitcoind \
  bin/btcheadernode/bin/bitcoin-cli
nodist_btcheadernodedoc_DATA += bin/btcheadernode/COPYING.bitcoin-core

$(BTCHEADERNODE_BIN_STAMP): $(top_srcdir)/contrib/btcheadernode/build-bitcoin-header-node.sh \
	$(top_srcdir)/contrib/btcheadernode/bitcoin.lock \
	$(top_srcdir)/contrib/btcheadernode/COPYING.bitcoin-core \
	$(top_srcdir)/contrib/btcheadernode/patches/headers-only.diff
	$(AM_V_at)HOST="$(host)" CC="$(CC)" CXX="$(CXX)" AR="$(AR)" RANLIB="$(RANLIB)" NM="$(NM)" STRIP="$(STRIP)" CPPFLAGS="$(CPPFLAGS)" CFLAGS="$(CFLAGS)" CXXFLAGS="$(CXXFLAGS)" LDFLAGS="$(LDFLAGS)" $(top_srcdir)/contrib/btcheadernode/build-bitcoin-header-node.sh --src-root "$(abs_top_srcdir)" --build-root "$(abs_top_builddir)"
	$(AM_V_at)mkdir -p "$(dir $@)"
	$(AM_V_at)touch "$@"

bin/btcheadernode/bin/bitcoind: $(BTCHEADERNODE_BIN_STAMP)
	@test -x "$@"

bin/btcheadernode/bin/bitcoin-cli: $(BTCHEADERNODE_BIN_STAMP)
	@test -x "$@"

bin/btcheadernode/COPYING.bitcoin-core: $(BTCHEADERNODE_BIN_STAMP)
	@test -f "$@"
endif
# if TARGET_ARM_LINUX
# dist_bin_SCRIPTS += bin/linux/arm/sysgeth
# endif
# if TARGET_AARCH64_LINUX
# dist_bin_SCRIPTS += bin/linux/aarch64/sysgeth
# endif


CTAES_DIST =  crypto/ctaes/bench.c
CTAES_DIST += crypto/ctaes/ctaes.c
CTAES_DIST += crypto/ctaes/ctaes.h
CTAES_DIST += crypto/ctaes/README.md
CTAES_DIST += crypto/ctaes/test.c

# SYSCOIN: Keep the exact research-profile provenance, licenses, and independent
# differential/KAT tooling in source distributions. These files are part of
# the review boundary even though they are not linked into binaries.
PQ_CRYPTO_DIST = \
  crypto/slhdsa/README.md \
  crypto/sphincs_c11/README.md \
  crypto/sphincs_c11/tests/standalone_test.cpp \
  crypto/sphincs_c11/tools/differential.py

# SYSCOIN: Binary packages must carry the exact third-party notices for both linked PQ
# implementations; the source-distribution list alone is insufficient.
slhdsadocdir = $(docdir)/pq-crypto/slhdsa
dist_slhdsadoc_DATA = crypto/slhdsa/LICENSE.upstream
sphincsc11docdir = $(docdir)/pq-crypto/sphincs_c11
dist_sphincsc11doc_DATA = crypto/sphincs_c11/LICENSE

CLEANFILES = $(EXTRA_LIBRARIES)
if ENABLE_BTCHEADERNODE_BUILD
CLEANFILES += bin/btcheadernode/.build-stamp
endif
CLEANFILES += *.gcda *.gcno
CLEANFILES += compat/*.gcda compat/*.gcno
CLEANFILES += consensus/*.gcda consensus/*.gcno
CLEANFILES += crc32c/src/*.gcda crc32c/src/*.gcno
CLEANFILES += crypto/*.gcda crypto/*.gcno
CLEANFILES += index/*.gcda index/*.gcno
CLEANFILES += interfaces/*.gcda interfaces/*.gcno
CLEANFILES += node/*.gcda node/*.gcno
CLEANFILES += policy/*.gcda policy/*.gcno
CLEANFILES += primitives/*.gcda primitives/*.gcno
CLEANFILES += rpc/*.gcda rpc/*.gcno
CLEANFILES += script/*.gcda script/*.gcno
CLEANFILES += support/*.gcda support/*.gcno
CLEANFILES += univalue/*.gcda univalue/*.gcno
CLEANFILES += util/*.gcda util/*.gcno
CLEANFILES += wallet/*.gcda wallet/*.gcno
CLEANFILES += wallet/test/*.gcda wallet/test/*.gcno
CLEANFILES += zmq/*.gcda zmq/*.gcno
CLEANFILES += obj/build.h


IMMER_DIST = immer/immer
EXTRA_DIST = \
  $(CTAES_DIST)   \
  $(IMMER_DIST)   \
  $(PQ_CRYPTO_DIST)

config/syscoin-config.h: config/stamp-h1
	@$(MAKE) -C $(top_builddir) $(subdir)/$(@)
config/stamp-h1: $(top_srcdir)/$(subdir)/config/syscoin-config.h.in $(top_builddir)/config.status
	$(AM_V_at)$(MAKE) -C $(top_builddir) $(subdir)/$(@)
$(top_srcdir)/$(subdir)/config/syscoin-config.h.in:  $(am__configure_deps)
	$(AM_V_at)$(MAKE) -C $(top_srcdir) $(subdir)/config/syscoin-config.h.in

# SYSCOIN: Legacy BLS no longer has a nested build tree to clean.
clean-local:
	-$(MAKE) -C secp256k1 clean
	-rm -f leveldb/*/*.gcda leveldb/*/*.gcno leveldb/helpers/memenv/*.gcda leveldb/helpers/memenv/*.gcno
	-rm -f config.h
	-rm -rf test/__pycache__
	-rm -rf *.dSYM test/*.dSYM bench/*.dSYM qt/*.dSYM qt/test/*.dSYM

.rc.o:
	@test -f $(WINDRES) || (echo "windres $(WINDRES) not found, but is required to compile windows resource files"; exit 1)
	## FIXME: How to get the appropriate modulename_CPPFLAGS in here?
	$(AM_V_GEN) $(WINDRES) $(DEFS) $(DEFAULT_INCLUDES) $(INCLUDES) $(CPPFLAGS) -DWINDRES_PREPROC -i $< -o $@

check-symbols: $(bin_PROGRAMS)
	@echo "Running symbol and dynamic library checks..."
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/symbol-check.py $(bin_PROGRAMS)

check-security: $(bin_PROGRAMS)
if HARDEN
	@echo "Checking binary security..."
	$(AM_V_at) $(PYTHON) $(top_srcdir)/contrib/devtools/security-check.py $(bin_PROGRAMS)
endif

osx_debug: $(bin_PROGRAMS)
	for i in $(bin_PROGRAMS); do mkdir -p $$i.dSYM/Contents/Resources/DWARF && $(DSYMUTIL_FLAT) -o $$i.dSYM/Contents/Resources/DWARF/$$(basename $$i) $$i &> /dev/null ; done

libsyscoin_ipc_mpgen_input = \
  ipc/capnp/echo.capnp \
  ipc/capnp/init.capnp
EXTRA_DIST += $(libsyscoin_ipc_mpgen_input)
%.capnp:

# Explicitly list dependencies on generated headers as described in
# https://www.gnu.org/software/automake/manual/html_node/Built-Sources-Example.html#Recording-Dependencies-manually
ipc/capnp/libsyscoin_ipc_a-protocol.$(OBJEXT): $(libsyscoin_ipc_mpgen_input:=.h)

if BUILD_MULTIPROCESS
LIBSYSCOIN_IPC=libsyscoin_ipc.a
libsyscoin_ipc_a_SOURCES = \
  ipc/capnp/context.h \
  ipc/capnp/init-types.h \
  ipc/capnp/protocol.cpp \
  ipc/capnp/protocol.h \
  ipc/context.h \
  ipc/exception.h \
  ipc/interfaces.cpp \
  ipc/process.cpp \
  ipc/process.h \
  ipc/protocol.h
libsyscoin_ipc_a_CPPFLAGS = $(AM_CPPFLAGS) $(SYSCOIN_INCLUDES)
libsyscoin_ipc_a_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS) $(LIBMULTIPROCESS_CFLAGS)

include $(MPGEN_PREFIX)/include/mpgen.mk
libsyscoin_ipc_mpgen_output = \
  $(libsyscoin_ipc_mpgen_input:=.c++) \
  $(libsyscoin_ipc_mpgen_input:=.h) \
  $(libsyscoin_ipc_mpgen_input:=.proxy-client.c++) \
  $(libsyscoin_ipc_mpgen_input:=.proxy-server.c++) \
  $(libsyscoin_ipc_mpgen_input:=.proxy-types.c++) \
  $(libsyscoin_ipc_mpgen_input:=.proxy-types.h) \
  $(libsyscoin_ipc_mpgen_input:=.proxy.h)
nodist_libsyscoin_ipc_a_SOURCES = $(libsyscoin_ipc_mpgen_output)
CLEANFILES += $(libsyscoin_ipc_mpgen_output)
endif

include Makefile.minisketch.include

include Makefile.crc32c.include
include Makefile.leveldb.include

include Makefile.test_util.include
include Makefile.test_fuzz.include

include Makefile.test.include

if ENABLE_BENCH
include Makefile.bench.include
endif

if ENABLE_QT
include Makefile.qt.include
endif

if ENABLE_QT_TESTS
include Makefile.qttest.include
endif

include Makefile.univalue.include
