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

#include <tools/ossfuzz/protoToShuffler.h>

#include <libyul/backends/evm/ssa/SSACFGTypes.h>

#include <algorithm>
#include <unordered_set>

namespace solidity::yul::ssa::shuffler_fuzzer
{

namespace
{

using ProtoSlot = ::solidity::yul::test::shuffler_fuzzer::Slot;
using ProtoInput = ::solidity::yul::test::shuffler_fuzzer::ShuffleInput;
using ValueId = SSACFG::ValueId;

/// Convert a single proto slot into a StackSlot, clamping the id into the
/// fuzzing id range so we get slot collisions rather than every mutation
/// producing a unique id.
StackSlot protoSlotToStackSlot(ProtoSlot const& _slot)
{
	std::uint32_t const id = _slot.id() % (kMaxSlotId + 1);
	switch (_slot.kind())
	{
	case ProtoSlot::V:
		return StackSlot::makeValueID(ValueId::makeVariable(id));
	case ProtoSlot::PHI:
		return StackSlot::makeValueID(ValueId::makePhi(id));
	case ProtoSlot::LIT:
		return StackSlot::makeValueID(ValueId::makeLiteral(id));
	case ProtoSlot::JUNK:
		return StackSlot::makeJunk();
	}
	// Unknown kind from wire (unlikely given proto2 required enum): treat as junk.
	return StackSlot::makeJunk();
}

/// A V or PHI slot can only appear in target_top / tail_set if it's present on
/// the initial stack — the shuffler cannot synthesise SSA values. Literals and
/// junk are freely generatable, so they're always OK.
bool isAvailable(StackSlot const& _slot, std::unordered_set<std::uint64_t> const& _initialValueKeys)
{
	if (_slot.isJunk())
		return true;
	if (!_slot.isValueID())
		return true;
	ValueId const vid = _slot.valueID();
	if (vid.kind() == ValueId::Kind::Literal)
		return true;
	std::uint64_t const key =
		(static_cast<std::uint64_t>(static_cast<std::uint8_t>(vid.kind())) << 32) |
		static_cast<std::uint64_t>(vid.value());
	return _initialValueKeys.contains(key);
}

std::uint64_t valueKey(ValueId const& _vid)
{
	return (static_cast<std::uint64_t>(static_cast<std::uint8_t>(_vid.kind())) << 32) |
		static_cast<std::uint64_t>(_vid.value());
}

} // anonymous namespace

ConvertedInput convertProtoInput(ProtoInput const& _input)
{
	ConvertedInput out;

	// --- 1. initial stack ---
	// Bound input length and translate each proto slot.
	{
		std::size_t const n = std::min<std::size_t>(
			static_cast<std::size_t>(_input.initial_size()),
			kMaxInitialSize
		);
		out.initial.reserve(n);
		for (std::size_t i = 0; i < n; ++i)
			out.initial.push_back(protoSlotToStackSlot(_input.initial(static_cast<int>(i))));
	}

	// Build a fast lookup of V/PHI values present on the initial stack.
	// (Literals and junk are freely generatable so we don't need to track them.)
	std::unordered_set<std::uint64_t> initialValueKeys;
	initialValueKeys.reserve(out.initial.size());
	for (auto const& slot: out.initial)
		if (slot.isValueID())
		{
			ValueId const vid = slot.valueID();
			if (vid.kind() == ValueId::Kind::Variable || vid.kind() == ValueId::Kind::Phi)
				initialValueKeys.insert(valueKey(vid));
		}

	// --- 2. target top ---
	// Cap size, then replace unavailable V/PHI slots with JUNK so the shuffler
	// precondition "every arg is on stack or freely generatable" holds.
	{
		std::size_t const n = std::min<std::size_t>(
			static_cast<std::size_t>(_input.target_top_size()),
			kMaxTargetTopSize
		);
		out.targetTop.reserve(n);
		for (std::size_t i = 0; i < n; ++i)
		{
			StackSlot slot = protoSlotToStackSlot(_input.target_top(static_cast<int>(i)));
			if (!isAvailable(slot, initialValueKeys))
				slot = StackSlot::makeJunk();
			out.targetTop.push_back(slot);
		}
	}

	// --- 3. tail set (liveness) ---
	// Rules:
	//   * No JUNK (parseLiveness in the upstream test harness asserts this).
	//   * Value ids only — V/PHI must be on the initial stack; Literals are OK.
	//   * Deduplicate by value id.
	LivenessAnalysis::LivenessData::LiveCounts liveCounts;
	{
		std::unordered_set<std::uint64_t> seen;
		std::size_t const n = static_cast<std::size_t>(_input.tail_set_size());
		liveCounts.reserve(std::min<std::size_t>(n, kMaxTargetSize));
		for (std::size_t i = 0; i < n && liveCounts.size() < kMaxTargetSize; ++i)
		{
			StackSlot const slot = protoSlotToStackSlot(_input.tail_set(static_cast<int>(i)));
			if (!slot.isValueID())
				continue; // drop JUNK
			ValueId const vid = slot.valueID();
			if (!isAvailable(slot, initialValueKeys))
				continue; // drop V/PHI not on initial stack
			std::uint64_t const key = valueKey(vid);
			if (!seen.insert(key).second)
				continue; // dedupe
			liveCounts.emplace_back(vid, /*count=*/1u);
		}
	}
	out.targetTail = LivenessAnalysis::LivenessData{std::move(liveCounts)};

	// --- 4. target stack size ---
	// Must satisfy: targetTop.size() <= targetStackSize and
	//               targetTail.size() <= targetStackSize - targetTop.size().
	// The available tail slots = targetStackSize - targetTop.size(), and we need
	// at least targetTail.size() of them. Any extra is padding.
	{
		std::size_t const minTail = out.targetTail.size();
		std::size_t const tailRoomCap = (kMaxTargetSize >= out.targetTop.size())
			? kMaxTargetSize - out.targetTop.size()
			: 0u;
		// How many tail slots beyond the liveness set; clamped so total ≤ kMaxTargetSize.
		std::size_t extraPadding = 0;
		if (tailRoomCap > minTail)
			extraPadding = static_cast<std::size_t>(_input.extra_tail_padding()) %
				(tailRoomCap - minTail + 1);
		std::size_t const tailSize = minTail + extraPadding;
		out.targetStackSize = out.targetTop.size() + tailSize;
	}

	return out;
}

}
