# Bitcoin baseline and selective import ledger

Audited Syscoin commit: `d5fc88adc9992a25f26641ddb174a76e7bf64407`.

The useful effective source comparison point is **Bitcoin 26.0rc3**, commit [`e4fef4ae65c68ebd34774700dc4801c24313d469`](https://github.com/bitcoin/bitcoin/commit/e4fef4ae65c68ebd34774700dc4801c24313d469), followed by selective imports. This identifies the broad source generation, not an exact unmodified Bitcoin release or a claim that every later backport has been catalogued.

## Why a normal merge-base gives the wrong answer

Modern Bitcoin updates were replayed into Syscoin with different commit identities. The old common ancestor `aeedd8a53b2df0ca2bf0429ce37f97cd45b35ba6` is from 2015 and does not describe the current source generation. Comparing all changes since that ancestor would wrongly attribute years of Bitcoin development to Syscoin.

The baseline was established using the local Git source history, patch comparison, and official Bitcoin release objects fetched from the Bitcoin repository. No source checkout was reset or switched.

## Last broad import sequence

| Syscoin import | Bitcoin source | Evidence / interpretation |
| --- | --- | --- |
| `c7ef4349e705f2ca4eab212c3dee821516a3eec5` | `96ec3b67a7a7f968d002e13d6fc227f69b7f07d7`, PR 28707 | Same historical-release-note patch. This closes the broad replay of Bitcoin development preceding the release-candidate imports. |
| `62c4d10746f665d2d31023329a5c2622a48971c1` | `7d0e5b099c71d6280315dffcfaf16835344e685f`, PR 28763 | 26.0rc2 translations. |
| `5379b5b4b099547e535294f884c3f5429de40461` | `67b25125603aacaa445bf6e9f0147789a039a679`, PR 28754 | rc2 source backports agree after product-name normalization. The additional functional-test `bump_mocktime(sleep)` to `bump_mocktime(2)` adjustment is a fork difference. |
| `12da5376c5e06b96cfde1465ed93874a7b8cd8f0` | rc3 `-par` help-text update | Imported separately immediately before the rc3 batch. |
| `434ceaef54f34f127d56228ae621dddfaacf8a08` | `e4fef4ae65c68ebd34774700dc4801c24313d469`, PR 28872 | rc3 substantive C++ source patches agree. The Syscoin batch additionally includes a fork-only `src/masternode/masternodepayments.cpp_` file. Version, manual-page, example-configuration, and release-publication differences are accounted for separately. |

Bitcoin rc3 is an ancestor of the official final v26.0 release. The rc3-to-final diff changes only `configure.ac`, six manual pages, and release notes. It does not introduce another C++ source generation. The audit nevertheless pins rc3 to match the actual import sequence.

## Known later selective imports

These examples are important exceptions to the rule “different from rc3 means fork-specific.” They are not an exhaustive provenance map for every generic cleanup candidate.

| Bitcoin PR | Syscoin commit | Recorded scope |
| --- | --- | --- |
| 28092 | `797493314d6a1f20dd578bc39633ee25f05f422a` | mingw-w64 `-Wreturn-type` documentation/build handling |
| 28999 | `705f606ae220aaa648af5341331b1c02e65a1293` | Enable `-Wunreachable-code` |
| 27872 | `12149171ce95bf30072c5f54f7beef90616c10be` | Suppress external warnings by default |
| 29486 | `a1b53d63d9b7a1d182a705da398aa146b9c95a95` | Remove `-Wdocumentation` conditional |
| 25972 | `fd503c8fe82d470c5494dcc205fb224e594ebd59` | Preserve `WARN_CXXFLAGS` when `CXXFLAGS` is set |
| These five PRs | `2a266da4a6b330a8fae569755014260243ae3ed7` | April 2025 umbrella build import, with CI adjustments |
| 23757, partial | `a291d25727ea6da31977e13e249836ab6bf72483` | Qt 5.15 GUI/test build fix |
| 30567 | `9304688885d9df8e9535ff137e841e8ce2695b51` | Qt `QT_STATICPLUGIN` removal was imported, then reverted by `09077e6a37ed23213ac8ac5c10ce84c4ff03bf10`; do not treat it as a currently retained import without checking the final diff. |

For a future merge, use rc3 as the historical comparison base, then reconcile these selective imports against the new Bitcoin target. Keep an unresolved/generic bucket for differences whose history has not yet established whether they are backports or fork adaptations. Commit author names and merge subjects alone do not prove ownership; imported patches can include local conflict-resolution edits.
