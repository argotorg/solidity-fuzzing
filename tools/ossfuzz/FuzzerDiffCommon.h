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

}
