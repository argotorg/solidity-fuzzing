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

#include <tools/ossfuzz/FuzzerDiffCommon.h>

#include <libsolutil/FixedHash.h>

#include <algorithm>
#include <cstring>
#include <string>

using namespace solidity::test;
using namespace solidity::test::fuzzer;
using namespace solidity::frontend;
using namespace solidity::util;

bool solidity::test::fuzzer::logsEqual(
	std::vector<evmc::MockedHost::log_record> const& _a,
	std::vector<evmc::MockedHost::log_record> const& _b
)
{
	if (_a.size() != _b.size())
		return false;
	for (size_t i = 0; i < _a.size(); i++)
		if (_a[i].data != _b[i].data || _a[i].topics != _b[i].topics)
			return false;
	return true;
}

std::map<evmc::address, StorageMap> solidity::test::fuzzer::filterZeroStorage(
	std::map<evmc::address, StorageMap> const& _storage
)
{
	static constexpr evmc::bytes32 zero{};
	std::map<evmc::address, StorageMap> filtered;
	for (auto const& [addr, storageMap] : _storage)
	{
		StorageMap nonZero;
		for (auto const& [key, val] : storageMap)
			if (val.current != zero)
				nonZero[key] = val;
		if (!nonZero.empty())
			filtered[addr] = std::move(nonZero);
	}
	return filtered;
}

std::map<evmc::address, TransientStorageMap> solidity::test::fuzzer::filterZeroTransientStorage(
	std::map<evmc::address, TransientStorageMap> const& _storage
)
{
	static constexpr evmc::bytes32 zero{};
	std::map<evmc::address, TransientStorageMap> filtered;
	for (auto const& [addr, storageMap] : _storage)
	{
		TransientStorageMap nonZero;
		for (auto const& [key, val] : storageMap)
			if (val != zero)
				nonZero[key] = val;
		if (!nonZero.empty())
			filtered[addr] = std::move(nonZero);
	}
	return filtered;
}

std::map<size_t, StorageMap> solidity::test::fuzzer::normalizeStorageByCreationOrder(
	std::map<evmc::address, StorageMap> const& _storage,
	std::vector<evmc::address> const& _creationOrder
)
{
	auto filtered = filterZeroStorage(_storage);
	std::map<size_t, StorageMap> result;
	size_t unknownIdx = _creationOrder.size();
	for (auto const& [addr, storageMap] : filtered)
	{
		auto it = std::find(_creationOrder.begin(), _creationOrder.end(), addr);
		size_t idx = (it != _creationOrder.end())
			? static_cast<size_t>(std::distance(_creationOrder.begin(), it))
			: unknownIdx++;
		result[idx] = storageMap;
	}
	return result;
}

std::map<size_t, TransientStorageMap> solidity::test::fuzzer::normalizeTransientStorageByCreationOrder(
	std::map<evmc::address, TransientStorageMap> const& _storage,
	std::vector<evmc::address> const& _creationOrder
)
{
	auto filtered = filterZeroTransientStorage(_storage);
	std::map<size_t, TransientStorageMap> result;
	size_t unknownIdx = _creationOrder.size();
	for (auto const& [addr, storageMap] : filtered)
	{
		auto it = std::find(_creationOrder.begin(), _creationOrder.end(), addr);
		size_t idx = (it != _creationOrder.end())
			? static_cast<size_t>(std::distance(_creationOrder.begin(), it))
			: unknownIdx++;
		result[idx] = storageMap;
	}
	return result;
}

bool solidity::test::fuzzer::storageEqual(
	std::map<evmc::address, StorageMap> const& _a,
	std::vector<evmc::address> const& _creationOrderA,
	std::map<evmc::address, StorageMap> const& _b,
	std::vector<evmc::address> const& _creationOrderB
)
{
	auto normA = normalizeStorageByCreationOrder(_a, _creationOrderA);
	auto normB = normalizeStorageByCreationOrder(_b, _creationOrderB);
	if (normA.size() != normB.size())
		return false;
	for (auto const& [idx, storageA] : normA)
	{
		auto jt = normB.find(idx);
		if (jt == normB.end())
			return false;
		auto const& storageB = jt->second;
		if (storageA.size() != storageB.size())
			return false;
		for (auto const& [key, valA] : storageA)
		{
			auto kt = storageB.find(key);
			if (kt == storageB.end())
				return false;
			if (valA.current != kt->second.current)
				return false;
		}
	}
	return true;
}

bool solidity::test::fuzzer::transientStorageEqual(
	std::map<evmc::address, TransientStorageMap> const& _a,
	std::vector<evmc::address> const& _creationOrderA,
	std::map<evmc::address, TransientStorageMap> const& _b,
	std::vector<evmc::address> const& _creationOrderB
)
{
	auto normA = normalizeTransientStorageByCreationOrder(_a, _creationOrderA);
	auto normB = normalizeTransientStorageByCreationOrder(_b, _creationOrderB);
	if (normA.size() != normB.size())
		return false;
	for (auto const& [idx, storageA] : normA)
	{
		auto jt = normB.find(idx);
		if (jt == normB.end())
			return false;
		auto const& storageB = jt->second;
		if (storageA.size() != storageB.size())
			return false;
		for (auto const& [key, valA] : storageA)
		{
			auto kt = storageB.find(key);
			if (kt == storageB.end())
				return false;
			if (valA != kt->second)
				return false;
		}
	}
	return true;
}

std::string solidity::test::fuzzer::buildOptimizerSequence(
	google::protobuf::RepeatedField<uint32_t> const& _steps
)
{
	// TODO: Remove this early return to re-enable random optimization sequences.
	// Currently disabled to use only the default sequence.
	(void)_steps;
	return OptimiserSettings::DefaultYulOptimiserSteps;
}

namespace
{

constexpr char const kInternalFunctionPrefix[] = "t_function_internal_";

void walkLayoutType(
	solidity::Json const& _types,
	std::string const& _typeKey,
	solidity::u256 const& _slot,
	unsigned _offset,
	std::vector<StorageSlotMask>& _out
)
{
	if (_typeKey.compare(0, sizeof(kInternalFunctionPrefix) - 1, kInternalFunctionPrefix) == 0)
	{
		// Internal function pointer field. solc emits numberOfBytes="8" for
		// these (storageBytes()=8, storageSize()=1); fall back to 8 if the
		// types entry is missing — the prefix alone is authoritative.
		unsigned length = 8;
		if (auto it = _types.find(_typeKey); it != _types.end())
			if (auto nb = it->find("numberOfBytes"); nb != it->end() && nb->is_string())
				length = static_cast<unsigned>(std::stoul(nb->get<std::string>()));
		_out.push_back({_slot, _offset, length});
		return;
	}

	auto typeIt = _types.find(_typeKey);
	if (typeIt == _types.end())
		return;
	solidity::Json const& typeInfo = *typeIt;

	auto encIt = typeInfo.find("encoding");
	if (encIt == typeInfo.end() || !encIt->is_string() || encIt->get<std::string>() != "inplace")
		return;  // mapping / dynamic_array / bytes — TODO: indirect-keyed storage

	if (auto membersIt = typeInfo.find("members"); membersIt != typeInfo.end() && membersIt->is_array())
	{
		// Struct: walk each member, translating its struct-relative slot/offset
		// into absolute coordinates within the contract's storage.
		for (auto const& member: *membersIt)
		{
			std::string mTypeKey = member.at("type").get<std::string>();
			solidity::u256 mSlotRel(member.at("slot").get<std::string>());
			unsigned mOffset = member.at("offset").get<unsigned>();
			walkLayoutType(_types, mTypeKey, _slot + mSlotRel, mOffset, _out);
		}
		return;
	}

	// Inplace static array (`base` key) or other inplace value type.
	// Static arrays of internal-fps are not currently exercised by any finding;
	// extend here if/when one is reduced (would need element-packing math from
	// the array's numberOfBytes and the base type's storageBytes).
}

}

std::vector<StorageSlotMask> solidity::test::fuzzer::internalFunctionPointerMasks(
	solidity::Json const& _layout
)
{
	std::vector<StorageSlotMask> out;
	if (!_layout.is_object())
		return out;
	auto storageIt = _layout.find("storage");
	auto typesIt = _layout.find("types");
	if (storageIt == _layout.end() || !storageIt->is_array() ||
		typesIt == _layout.end() || !typesIt->is_object())
		return out;

	for (auto const& var: *storageIt)
	{
		std::string typeKey = var.at("type").get<std::string>();
		solidity::u256 slot(var.at("slot").get<std::string>());
		unsigned offset = var.at("offset").get<unsigned>();
		walkLayoutType(*typesIt, typeKey, slot, offset, out);
	}
	return out;
}

void solidity::test::fuzzer::applyStorageMasks(
	std::map<evmc::address, StorageMap>& _storage,
	evmc::address const& _address,
	std::vector<StorageSlotMask> const& _masks
)
{
	if (_masks.empty())
		return;
	auto accIt = _storage.find(_address);
	if (accIt == _storage.end())
		return;
	StorageMap& slots = accIt->second;
	static constexpr evmc::bytes32 zero{};

	for (auto const& mask: _masks)
	{
		if (mask.length == 0 || mask.length > 32 || mask.offset >= 32 || mask.offset + mask.length > 32)
			continue;
		// Slots are big-endian 32-byte keys; first item in a slot is stored
		// lower-order aligned, so a value at byte-offset O of length L occupies
		// bytes32[32 - O - L .. 32 - O) in the big-endian array.
		evmc::bytes32 key = solidity::test::EVMHost::convertToEVMC(h256(mask.slot));
		auto slotIt = slots.find(key);
		if (slotIt == slots.end())
			continue;
		evmc::bytes32& current = slotIt->second.current;
		unsigned const hi = 32 - mask.offset;
		unsigned const lo = hi - mask.length;
		for (unsigned i = lo; i < hi; ++i)
			current.bytes[i] = 0;
		// Drop fully-zero slots so they don't show up in the
		// post-filterZeroStorage comparison as a spurious one-sided entry.
		if (current == zero)
			slots.erase(slotIt);
	}
}
