# RPC, wallet, and GUI provenance triage

Bitcoin baseline: `e4fef4ae65c68ebd34774700dc4801c24313d469` (26.0rc3).
Syscoin target: `d5fc88adc9992a25f26641ddb174a76e7bf64407`.

These ten groups were checked against the actual target source and the Bitcoin diff. They are confirmed missing or ambiguous provenance boundaries, not runtime defects. Line numbers refer to the pinned target. All recommendations concern comments only.

| ID | Target location | Confirmed fork change and recommended boundary |
| --- | --- | --- |
| R01 | `src/wallet/salvage.cpp:149–171` | **Missing.** The pre-rename scan refuses wallets containing PQ voting secrets, their mandatory flag, or unclassifiable records. Wrap the comment and complete loop in SYSCOIN BEGIN/END, ending before the ordinary Bitcoin backup filename/rename at line 173. The existing safety explanation describes behavior but has no SYSCOIN provenance tag. |
| R02 | `src/wallet/wallet.h:310–313` | **Missing.** The plaintext/encrypted SLH-DSA voting-key maps and `CheckVotingDecryptionKey` declaration extend Bitcoin's private wallet state. Give this contiguous addition its own pair, keeping upstream `vMasterKey` and `Unlock` outside the region. |
| R03 | `src/wallet/walletdb.cpp:160–175,1189–1218` | **Missing.** `WriteVotingKey`, `WriteCryptedVotingKey`, and `LoadVotingKeys` add independent PQ voting-key records, encryption/checksum handling, and strict parsing. Use a pair around the two write helpers and another around the load helper; stop before the neighboring Bitcoin wallet methods. These are absent from the baseline and use fork-specific record keys. |
| R04 | `src/wallet/wallet.cpp:1116–1127,1155–1156` | **Missing.** `EncryptWallet` encrypts voting secrets in the same database transaction and updates their in-memory maps after commit. Mark the inserted encryption loop and the post-commit map transition separately, preserving the upstream script-manager encryption and transaction commit between them. |
| R05 | `src/wallet/walletutil.h:79–80` | **Missing.** `WALLET_FLAG_PQ_VOTING_KEYS` is a mandatory compatibility bit for independent secrets. An inline SYSCOIN annotation or adjacent two-line marker should identify this enum addition; the ordinary wallet flags remain upstream. |
| R06 | `src/rpc/blockchain.cpp:1343–1349` | **Missing.** `verifychain` handles `UNSUPPORTED_CHECK_LEVEL` explicitly and returns a PQ-activation-specific error for check level 4. Mark this replacement of Bitcoin's direct success comparison. Do not tag the entire RPC implementation as new code. |
| R07 | `src/rpc/blockchain.cpp:111–144`; `src/rpc/rawtransaction.cpp:54–56` | **Missing helper / partly annotated API adaptation.** `AuxpowToJSON` is a fork helper and needs a complete pair. Its call to `TxToJSON` relies on making Bitcoin's static helper externally visible and moving default arguments to a header declaration. That header declaration already has SYSCOIN at `src/rpc/rawtransaction_util.h:55–56`; add a narrow explanatory marker to the definition signature. **The Chainstate parameter and ordinary helper body already exist in Bitcoin** and should not be claimed as fork additions. |
| R08 | `src/rpc/rawtransaction.cpp:135–223` | **Partly marked.** The added `systx`, provider, coinbase, and quorum JSON schemas extend transaction decoding. Existing bounded comments describe some recent provider-key field edits, while the older enclosing fork schemas have no clear region boundary. Add a pair around the complete added schema region, preserving the useful nested field-specific comments. The earlier bare asset marker at line 130 introduces a different nested output object. |
| R09 | `src/wallet/rpc/coins.cpp:554–555` | **Missing.** `listunspent` adds optional asset GUID/amount output fields to the Bitcoin RPC schema. Give the two fields a local marker, without claiming the surrounding ordinary coin fields. |
| R10 | `src/qt/rpcconsole.cpp:1235–1246` | **Missing.** Peer details now look up the deterministic masternode list, distinguish regular/unverified/verified masternodes, and show the PoSe score. Put a pair around that complete block, ending before the upstream node-state availability comment at line 1247. |

## Exclusions and limits

- Product renames alone are not substantive marker omissions.
- Generic RPC namespace, signature, serialization, and cleanup differences require provenance review. In particular, the `Chainstate` parameter in `TxToJSON` was already upstream; its fork adaptation is external linkage for the AuxPoW caller.
- Existing SYSCOIN annotations on individual provider JSON fields are useful. R08 concerns the incomplete enclosing boundary, not the absence of every marker.
- This is a bounded verified subset of RPC/wallet/GUI candidates. The full automated inventory retains the other candidates for later review.

No production source was modified and no runtime validation was performed for this comments-only audit.
