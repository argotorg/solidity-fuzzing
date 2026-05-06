/*
	This file is part of solidity.

	solidity is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	solidity is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with solidity.  If not, see <http://www.gnu.org/licenses/>.
*/
// SPDX-License-Identifier: GPL-3.0
/**
 * Shared utilities for differential fuzzers that compare two EVM runs.
 *
 * Provides RunResult capture, storage/log comparison functions, and
 * optimizer sequence building — used by both the Solidity and Yul
 * differential fuzzers.
 */

#pragma once

#include <tools/common/EVMHost.h>

#include <libsolidity/interface/OptimiserSettings.h>
#include <libsolutil/JSON.h>

#include <test/evmc/mocked_host.hpp>

#include <map>
#include <unordered_map>
#include <vector>
#include <cstdint>

namespace google::protobuf { template<typename T> class RepeatedField; }

namespace solidity::test::fuzzer
{

/// Transient storage map type: slot -> value (no StorageValue wrapper).
using TransientStorageMap = std::unordered_map<evmc::bytes32, evmc::bytes32>;

/// Result of a single compile-deploy-execute run, including EVM result,
/// recorded logs, and storage state for differential comparison.
struct RunResult
{
	evmc::Result result;
	bool subCallOutOfGas = false;
	std::vector<evmc::MockedHost::log_record> logs;
	std::map<evmc::address, StorageMap> storage;
	std::map<evmc::address, TransientStorageMap> transientStorage;
	/// Contract creation order: addresses in the order they were deployed (CREATE/CREATE2).
	std::vector<evmc::address> contractCreationOrder;
	/// solc storage-layout JSON for the *main* compiled contract (the one
	/// at contractCreationOrder[0]). Used to mask internal-function-pointer
	/// fields whose encoding is not portable across optimiser/codegen modes.
	/// Empty if compilation didn't run or the layout was unavailable.
	solidity::Json mainContractStorageLayout;
};

/// Compare two log records for equality (ignoring creator address,
/// which differs across optimization levels because different bytecodes
/// produce different CREATE/CREATE2 addresses).
bool logsEqual(
	std::vector<evmc::MockedHost::log_record> const& _a,
	std::vector<evmc::MockedHost::log_record> const& _b
);

/// Filter out storage entries where current value is zero.
/// In the EVM, an unwritten slot reads as zero, so a slot explicitly
/// set to zero is semantically identical to one that was never written.
std::map<evmc::address, StorageMap> filterZeroStorage(
	std::map<evmc::address, StorageMap> const& _storage
);

/// Filter out transient storage entries where value is zero.
std::map<evmc::address, TransientStorageMap> filterZeroTransientStorage(
	std::map<evmc::address, TransientStorageMap> const& _storage
);

/// Build a map from creation-order index to non-zero storage content.
/// Accounts not found in creationOrder (e.g. precompiles, sender) are
/// assigned indices starting after the last creation-order entry.
std::map<size_t, StorageMap> normalizeStorageByCreationOrder(
	std::map<evmc::address, StorageMap> const& _storage,
	std::vector<evmc::address> const& _creationOrder
);

/// Build a map from creation-order index to non-zero transient storage content.
/// Accounts not found in creationOrder are assigned indices after the last entry.
std::map<size_t, TransientStorageMap> normalizeTransientStorageByCreationOrder(
	std::map<evmc::address, TransientStorageMap> const& _storage,
	std::vector<evmc::address> const& _creationOrder
);

/// Compare storage maps for equality (comparing current values only).
/// Accounts are matched by CONTRACT CREATION ORDER (not by address), so that
/// different bytecodes producing different CREATE/CREATE2 addresses don't cause
/// false positives. Slots with value zero are filtered out (equivalent to unwritten).
bool storageEqual(
	std::map<evmc::address, StorageMap> const& _a,
	std::vector<evmc::address> const& _creationOrderA,
	std::map<evmc::address, StorageMap> const& _b,
	std::vector<evmc::address> const& _creationOrderB
);

/// Compare transient storage maps for equality.
/// Accounts are matched by CONTRACT CREATION ORDER (not by address), same
/// rationale as storageEqual. Slots with value zero are filtered out.
bool transientStorageEqual(
	std::map<evmc::address, TransientStorageMap> const& _a,
	std::vector<evmc::address> const& _creationOrderA,
	std::map<evmc::address, TransientStorageMap> const& _b,
	std::vector<evmc::address> const& _creationOrderB
);

/// Maps a sequence of uint32 values to a Yul optimizer step abbreviation string.
/// Currently disabled (returns the default sequence) — see TODO in implementation.
std::string buildOptimizerSequence(
	google::protobuf::RepeatedField<uint32_t> const& _steps
);

/// Byte range within a single storage slot that should be ignored when
/// comparing storage across optimiser/codegen configurations. Used to zero
/// out internal-function-pointer fields, whose encoding is not portable
/// (legacy stores `(creationPC<<32)|runtimePC` while IR stores a sequential
/// function ID — see TODO.md for context).
struct StorageSlotMask
{
	solidity::u256 slot;
	unsigned offset;  ///< 0..31, byte offset within the slot
	unsigned length;  ///< number of bytes to mask
};

/// Walk a solc storage-layout JSON (see
/// https://docs.soliditylang.org/en/latest/internals/layout_in_storage.html#json-output)
/// and emit a mask range for every internal-function-pointer field reachable
/// via inplace storage (top-level state vars, struct members, struct-of-struct,
/// inplace static arrays). Indirect-keyed storage (mappings, dynamic arrays,
/// bytes/string) is intentionally skipped — covering it would require knowing
/// the runtime keys, and so far no fuzzer corpus has exercised that path. Add
/// it if/when a finding actually needs it.
std::vector<StorageSlotMask> internalFunctionPointerMasks(
	solidity::Json const& _storageLayout
);

/// Apply @p _masks to the storage at @p _address in @p _storage: zero out the
/// listed byte ranges in each slot's `current` value. If a slot becomes
/// all-zero after masking, it is dropped from the map (matches the unwritten-
/// equals-zero convention used by storageEqual / filterZeroStorage). No-op if
/// @p _address has no entry in @p _storage or @p _masks is empty.
void applyStorageMasks(
	std::map<evmc::address, StorageMap>& _storage,
	evmc::address const& _address,
	std::vector<StorageSlotMask> const& _masks
);

}
