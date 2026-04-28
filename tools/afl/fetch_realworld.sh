#!/usr/bin/env bash
# Fetch major real-world Solidity projects into realworld_cache/ for use as
# AFL++ seed corpus. Idempotent — skips repos already cloned. All clones are
# --depth 1 (no history) to keep the cache small.
#
# Edit the REPOS list below to add/remove projects. After fetching, build the
# merged corpus with tools/afl/build_corpus.sh — it walks realworld_cache/
# automatically when the directory exists.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CACHE="${CACHE:-$REPO_ROOT/realworld_cache}"

# name|url — one per line. Edit freely. Names become subdirectory names under
# the cache, so keep them filesystem-safe.
REPOS=(
    "openzeppelin-contracts|https://github.com/OpenZeppelin/openzeppelin-contracts.git"
    "solady|https://github.com/Vectorized/solady.git"
    "solmate|https://github.com/transmissions11/solmate.git"
    "aave-v3-core|https://github.com/aave/aave-v3-core.git"
    "aave-v3-periphery|https://github.com/aave/aave-v3-periphery.git"
    "uniswap-v4-core|https://github.com/Uniswap/v4-core.git"
    "uniswap-v3-core|https://github.com/Uniswap/v3-core.git"
    "safe-smart-account|https://github.com/safe-global/safe-smart-account.git"
    "cowprotocol-contracts|https://github.com/cowprotocol/contracts.git"
    "compound-comet|https://github.com/compound-finance/comet.git"
    "lido-core|https://github.com/lidofinance/core.git"
    "ens-contracts|https://github.com/ensdomains/ens-contracts.git"
    "prb-math|https://github.com/PaulRBerg/prb-math.git"
    "forge-std|https://github.com/foundry-rs/forge-std.git"
    "weth9|https://github.com/gnosis/canonical-weth.git"
)

mkdir -p "$CACHE"

cloned=0
skipped=0
failed=0
failed_names=()

for entry in "${REPOS[@]}"; do
    name="${entry%%|*}"
    url="${entry##*|}"
    dest="$CACHE/$name"
    if [[ -d "$dest/.git" ]]; then
        echo "[skip] $name (already cloned)"
        skipped=$((skipped + 1))
        continue
    fi
    echo "[clone] $name <- $url"
    if git clone --depth 1 --quiet "$url" "$dest"; then
        cloned=$((cloned + 1))
    else
        echo "  FAILED" >&2
        failed=$((failed + 1))
        failed_names+=("$name")
        rm -rf "$dest"
    fi
done

echo
echo "Done. Cloned: $cloned   Skipped: $skipped   Failed: $failed"
if (( failed > 0 )); then
    echo "Failed clones: ${failed_names[*]}" >&2
    exit 1
fi
