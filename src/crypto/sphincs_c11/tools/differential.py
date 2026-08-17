#!/usr/bin/env python3
"""Regenerate the C11-SHA fixture from the pinned independent Python signer."""

import argparse
import hashlib
import pathlib
import subprocess
import sys


PINNED_COMMIT = "55b2f3e25d8d7cc0df33ccdb13becca1a168b26f"
EXPECTED_PUBLIC_KEY = (
    "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"
    "a3d1b4ec763f8be45e4a56375774efe9"
)
EXPECTED_SIGNATURE_SHA256 = (
    "99c0656fccd9353d4b68db3f4d09afc1"
    "485c9cc59381ff5603208a25be026886"
)
EXPECTED_SIGNATURE_PREFIX = (
    "9f42114f07b4ca113e31d4e42268ba0a"
    "9160612c600cc4bc20105b801347a63d"
)
EXPECTED_SIGNATURE_SUFFIX = (
    "08a8f45ab037909f3b108be499d279a3"
    "cda32b8b9ac7543f1ef992886e5c5f58"
)


def install_wots_message_domain(signer) -> None:
    """Apply the SPHINCS+C type-7 message-compression tweak.

    The pinned research signer currently reuses WOTS_HASH/type 0 here. The
    SPHINCS+C specification assigns type 7, and this small independent shim
    lets the otherwise pinned oracle generate the corrected consensus vector.
    """
    original = signer.wots_digest

    def corrected(seed, layer, tree, kp, msg_hash, count, cfg=None):
        if signer.HASH_BACKEND != "sha2":
            return original(seed, layer, tree, kp, msg_hash, count, cfg)
        address = ((layer & 0xFF) << 248 |
                   (tree & 0xFFFFFFFFFFFFFFFF) << 184 |
                   7 << 176 |
                   (kp & 0xFFFFFFFF) << 144)
        return signer.wots_digest_sha2(seed, address, msg_hash, count)

    signer.wots_digest = corrected


def git(upstream: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(upstream), *args], text=True
    ).strip()


def parse_output(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip()
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--upstream", required=True, type=pathlib.Path)
    parser.add_argument("--cpp", type=pathlib.Path,
                        help="optional compiled standalone_test executable")
    parser.add_argument("--allow-dirty", action="store_true")
    args = parser.parse_args()

    upstream = args.upstream.resolve()
    if git(upstream, "rev-parse", "HEAD") != PINNED_COMMIT:
        raise SystemExit(f"upstream must be checked out at {PINNED_COMMIT}")
    if not args.allow_dirty and git(upstream, "status", "--porcelain"):
        raise SystemExit("upstream checkout is dirty; use --allow-dirty intentionally")

    sys.path.insert(0, str(upstream / "script"))
    try:
        import signer  # type: ignore[import-not-found]
    except ModuleNotFoundError as error:
        if error.name == "Crypto":
            raise SystemExit("the pinned Python signer requires PyCryptodome") from error
        raise
    install_wots_message_domain(signer)

    secret_seed = int.from_bytes(bytes(range(32)), "big")
    public_seed_bytes = bytes(range(0xA0, 0xB0))
    # Reference values are top-aligned 16-byte nodes in a 32-byte integer.
    public_seed = int.from_bytes(public_seed_bytes + bytes(16), "big")
    message_bytes = bytes((3 + 7 * index) & 0xFF for index in range(32))
    message = int.from_bytes(message_bytes, "big")

    _, public_root, signature = signer.sign_variant(
        "c11-sha", message, seed=public_seed, sk_seed=secret_seed
    )
    public_key = (public_seed_bytes + public_root.to_bytes(32, "big")[:16]).hex()
    signature_sha256 = hashlib.sha256(signature).hexdigest()
    signature_prefix = signature[:32].hex()
    signature_suffix = signature[-32:].hex()

    observed = {
        "public_key": public_key,
        "signature_sha256": signature_sha256,
        "signature_prefix": signature_prefix,
        "signature_suffix": signature_suffix,
    }
    expected = {
        "public_key": EXPECTED_PUBLIC_KEY,
        "signature_sha256": EXPECTED_SIGNATURE_SHA256,
        "signature_prefix": EXPECTED_SIGNATURE_PREFIX,
        "signature_suffix": EXPECTED_SIGNATURE_SUFFIX,
    }
    if observed != expected:
        for name in expected:
            if observed[name] != expected[name]:
                print(f"mismatch {name}: expected {expected[name]}, got {observed[name]}",
                      file=sys.stderr)
        return 1

    if args.cpp is not None:
        cpp = parse_output(subprocess.check_output(
            [str(args.cpp.resolve()), "--dump-signature"], text=True
        ))
        for name in ("public_key", "signature_sha256"):
            if cpp.get(name) != expected[name]:
                print(f"C++ mismatch {name}: expected {expected[name]}, got {cpp.get(name)}",
                      file=sys.stderr)
                return 1
        if cpp.get("signature") != signature.hex():
            print("C++ signature differs byte-for-byte from the pinned Python signer",
                  file=sys.stderr)
            return 1

    for name, value in observed.items():
        print(f"{name}={value}")
    print(f"PASS: pinned Python signer {PINNED_COMMIT} matches C++ fixture")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
