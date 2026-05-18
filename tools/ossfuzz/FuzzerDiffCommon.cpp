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
#include <libsolutil/Keccak256.h>

#include <algorithm>
#include <cstdint>
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

/// Upper bound on dynamic-array element count we expand into per-element
/// masks. A pathological fuzzer input could declare an enormous length; past
/// this we abandon precise masking and let the caller skip the comparison
/// (a real corpus array of internal fps is a handful of elements).
constexpr uint64_t kMaxMaskedArrayElements = 4096;

/// Recursion guard for the type-tree walk (recursive structs etc.).
constexpr unsigned kMaxWalkDepth = 64;

bool isInternalFunctionType(std::string const& _typeKey)
{
	return _typeKey.compare(0, sizeof(kInternalFunctionPrefix) - 1, kInternalFunctionPrefix) == 0;
}

/// numberOfBytes for a type key; 0 if the type or the field is missing.
unsigned typeNumberOfBytes(solidity::Json const& _types, std::string const& _typeKey)
{
	if (auto it = _types.find(_typeKey); it != _types.end())
		if (auto nb = it->find("numberOfBytes"); nb != it->end() && nb->is_string())
			return static_cast<unsigned>(std::stoul(nb->get<std::string>()));
	return 0;
}

/// Structural check: does @p _typeKey contain an internal-function-pointer
/// anywhere in its type tree? Used to decide whether a mapping (whose runtime
/// keys we cannot enumerate) makes the storage comparison unreliable, and to
/// prune array walks that cannot contain anything maskable.
bool typeContainsInternalFunction(
	solidity::Json const& _types,
	std::string const& _typeKey,
	unsigned _depth = 0
)
{
	if (isInternalFunctionType(_typeKey))
		return true;
	if (_depth > kMaxWalkDepth)
		return false;
	auto it = _types.find(_typeKey);
	if (it == _types.end())
		return false;
	if (auto base = it->find("base"); base != it->end() && base->is_string())
		if (typeContainsInternalFunction(_types, base->get<std::string>(), _depth + 1))
			return true;
	if (auto value = it->find("value"); value != it->end() && value->is_string())
		if (typeContainsInternalFunction(_types, value->get<std::string>(), _depth + 1))
			return true;
	if (auto members = it->find("members"); members != it->end() && members->is_array())
		for (auto const& m: *members)
			if (typeContainsInternalFunction(_types, m.at("type").get<std::string>(), _depth + 1))
				return true;
	return false;
}

/// State threaded through the layout walk.
struct WalkContext
{
	solidity::Json const& types;       ///< the layout's "types" object
	StorageMap const& storage;         ///< main account storage (for array lengths)
	std::vector<StorageSlotMask>& out; ///< collected masks
	bool& unmaskable;                  ///< set when an internal fp is unreachable for masking
};

/// Read a dynamic-array length from the main account's storage at @p _slot.
/// Returns 0 if the slot was never written (an empty array).
solidity::u256 readArrayLength(StorageMap const& _storage, solidity::u256 const& _slot)
{
	evmc::bytes32 key = EVMHost::convertToEVMC(h256(_slot));
	auto it = _storage.find(key);
	if (it == _storage.end())
		return 0;
	return solidity::u256(EVMHost::convertFromEVMC(it->second.current));
}

void walkLayoutType(
	WalkContext& _ctx,
	std::string const& _typeKey,
	solidity::u256 const& _slot,
	unsigned _offset,
	unsigned _depth
);

/// Emit masks for @p _count elements of an array whose data starts at slot
/// @p _dataSlot. Small element types pack several per slot (internal fps are
/// 8 bytes -> 4 per slot); structs and nested arrays occupy whole slots. The
/// element type is recursed into, so structs/arrays-of-fps are handled too.
void walkArrayElements(
	WalkContext& _ctx,
	std::string const& _elemTypeKey,
	solidity::u256 const& _dataSlot,
	uint64_t _count,
	unsigned _depth
)
{
	unsigned elemBytes = typeNumberOfBytes(_ctx.types, _elemTypeKey);
	if (elemBytes == 0 || elemBytes > 32)
		return;
	if (elemBytes <= 16)
	{
		// Packed: floor(32/elemBytes) elements per slot, lower-order aligned.
		unsigned perSlot = 32u / elemBytes;
		for (uint64_t i = 0; i < _count; ++i)
			walkLayoutType(
				_ctx,
				_elemTypeKey,
				_dataSlot + (i / perSlot),
				static_cast<unsigned>((i % perSlot) * elemBytes),
				_depth + 1
			);
	}
	else
	{
		// One whole slot per element (a 17..32-byte value, e.g. external fp).
		for (uint64_t i = 0; i < _count; ++i)
			walkLayoutType(_ctx, _elemTypeKey, _dataSlot + i, 0, _depth + 1);
	}
}

void walkLayoutType(
	WalkContext& _ctx,
	std::string const& _typeKey,
	solidity::u256 const& _slot,
	unsigned _offset,
	unsigned _depth
)
{
	if (_depth > kMaxWalkDepth)
		return;

	if (isInternalFunctionType(_typeKey))
	{
		// Internal function pointer field. solc emits numberOfBytes="8" for
		// these (storageBytes()=8); fall back to 8 if the types entry is
		// missing — the prefix alone is authoritative.
		unsigned length = typeNumberOfBytes(_ctx.types, _typeKey);
		if (length == 0)
			length = 8;
		_ctx.out.push_back({_slot, _offset, length});
		return;
	}

	auto typeIt = _ctx.types.find(_typeKey);
	if (typeIt == _ctx.types.end())
		return;
	solidity::Json const& typeInfo = *typeIt;

	auto encIt = typeInfo.find("encoding");
	std::string encoding =
		(encIt != typeInfo.end() && encIt->is_string()) ? encIt->get<std::string>() : std::string{};

	if (encoding == "mapping")
	{
		// Mapping values live at keccak(key . slot); we cannot enumerate the
		// runtime keys. If an internal fp is reachable through one, masking is
		// impossible — signal the caller to skip the storage comparison.
		if (auto v = typeInfo.find("value"); v != typeInfo.end() && v->is_string())
			if (typeContainsInternalFunction(_ctx.types, v->get<std::string>()))
				_ctx.unmaskable = true;
		return;
	}

	if (encoding == "bytes")
		return;  // bytes/string cannot contain function pointers

	if (encoding == "dynamic_array")
	{
		auto baseIt = typeInfo.find("base");
		if (baseIt == typeInfo.end() || !baseIt->is_string())
			return;
		std::string baseKey = baseIt->get<std::string>();
		if (!typeContainsInternalFunction(_ctx.types, baseKey))
			return;
		solidity::u256 len = readArrayLength(_ctx.storage, _slot);
		if (len > kMaxMaskedArrayElements)
		{
			_ctx.unmaskable = true;
			return;
		}
		// The element data lives at keccak256 of the big-endian 32-byte slot
		// number that holds the array's length.
		solidity::u256 dataSlot(keccak256(h256(_slot)));
		walkArrayElements(_ctx, baseKey, dataSlot, static_cast<uint64_t>(len), _depth);
		return;
	}

	// encoding == "inplace" (or unspecified): struct, static array, or value.
	if (auto membersIt = typeInfo.find("members"); membersIt != typeInfo.end() && membersIt->is_array())
	{
		// Struct: walk each member, translating its struct-relative slot/offset
		// into absolute coordinates within the contract's storage.
		for (auto const& member: *membersIt)
		{
			std::string mTypeKey = member.at("type").get<std::string>();
			solidity::u256 mSlotRel(member.at("slot").get<std::string>());
			unsigned mOffset = member.at("offset").get<unsigned>();
			walkLayoutType(_ctx, mTypeKey, _slot + mSlotRel, mOffset, _depth + 1);
		}
		return;
	}

	if (auto baseIt = typeInfo.find("base"); baseIt != typeInfo.end() && baseIt->is_string())
	{
		// Inplace static array. It begins at offset 0 of its own slot (Solidity
		// always slot-aligns arrays). The element count is arrayBytes/elemBytes:
		// exact for internal fps (8 bytes, pack perfectly) and struct elements
		// (32-byte multiples); any over-count only masks trailing slot padding,
		// which is guaranteed zero and therefore a harmless no-op.
		std::string baseKey = baseIt->get<std::string>();
		if (!typeContainsInternalFunction(_ctx.types, baseKey))
			return;
		unsigned arrayBytes = typeNumberOfBytes(_ctx.types, _typeKey);
		unsigned elemBytes = typeNumberOfBytes(_ctx.types, baseKey);
		if (arrayBytes == 0 || elemBytes == 0)
			return;
		walkArrayElements(_ctx, baseKey, _slot, arrayBytes / elemBytes, _depth);
		return;
	}
	// Plain inplace value type that is not an internal fp: nothing to mask.
}

}

solidity::test::fuzzer::StorageMaskResult solidity::test::fuzzer::internalFunctionPointerMasks(
	solidity::Json const& _layout,
	std::map<evmc::address, StorageMap> const& _storage,
	std::vector<evmc::address> const& _creationOrder
)
{
	StorageMaskResult result;
	if (!_layout.is_object())
		return result;
	auto storageIt = _layout.find("storage");
	auto typesIt = _layout.find("types");
	if (storageIt == _layout.end() || !storageIt->is_array() ||
		typesIt == _layout.end() || !typesIt->is_object())
		return result;

	// Dynamic-array lengths are read from the main contract's storage.
	static StorageMap const emptyStorage;
	StorageMap const* mainStorage = &emptyStorage;
	if (!_creationOrder.empty())
		if (auto it = _storage.find(_creationOrder.front()); it != _storage.end())
			mainStorage = &it->second;

	WalkContext ctx{*typesIt, *mainStorage, result.masks, result.unmaskable};
	for (auto const& var: *storageIt)
	{
		std::string typeKey = var.at("type").get<std::string>();
		solidity::u256 slot(var.at("slot").get<std::string>());
		unsigned offset = var.at("offset").get<unsigned>();
		walkLayoutType(ctx, typeKey, slot, offset, 0);
	}
	return result;
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
