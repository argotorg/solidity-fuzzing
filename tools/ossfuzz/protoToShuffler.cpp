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

#include <libyul/backends/evm/ssa/InstructionStore.h>
#include <libyul/backends/evm/ssa/SSACFGTypes.h>

#include <cstddef>
#include <map>
#include <set>
#include <utility>

namespace solidity::yul::ssa::shuffler_fuzzer
{

namespace
{

using ProtoSlot = ::solidity::yul::test::shuffler_fuzzer::Slot;
using ProtoInput = ::solidity::yul::test::shuffler_fuzzer::ShuffleInput;

} // anonymous namespace

ConvertedInput convertProtoInput(ProtoInput const& _input)
{
	ConvertedInput out;

	// On `develop` a StackSlot of kind Value just carries an InstId; the defining
	// instruction lives in an InstructionStore. We build a throwaway store here
	// purely to mint InstIds — the resulting StackSlots are self-contained
	// (they cache the opcode) and outlive the store fine.
	InstructionStore store;

	// Memoize (kind, clamped-id) -> InstId so repeated proto slots collapse onto
	// the same StackSlot. Each appendXxx() hands out a *fresh* InstId, so without
	// this every proto slot would be unique and we'd never get the slot
	// collisions (duplicates) where the interesting shuffling logic lives.
	std::map<std::pair<int, std::uint32_t>, InstId> slotMemo;

	// Convert a single proto slot into a StackSlot, clamping the id into the
	// fuzzing id range so we get slot collisions rather than every mutation
	// producing a unique id. JUNK and unknown wire kinds become junk slots.
	auto const protoSlotToStackSlot = [&](ProtoSlot const& _slot) -> StackSlot
	{
		auto const kind = _slot.kind();
		if (kind != ProtoSlot::V && kind != ProtoSlot::PHI && kind != ProtoSlot::LIT)
			return StackSlot::makeJunk();

		std::uint32_t const id = _slot.id() % (kMaxSlotId + 1);
		auto const memoKey = std::pair{static_cast<int>(kind), id};
		auto it = slotMemo.find(memoKey);
		if (it == slotMemo.end())
		{
			InstId const instId =
				kind == ProtoSlot::PHI ? store.appendPhi({0}) :
				kind == ProtoSlot::LIT ? store.appendLiteral({0}, u256(id)) :
				store.appendBuiltinCall({0}, {}, {});
			it = slotMemo.emplace(memoKey, instId).first;
		}
		return StackSlot::makeValue(store, it->second);
	};

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

	// Build a fast lookup of every value slot present on the initial stack.
	// Anything not in this set, and not JUNK, is off-limits for target_top /
	// tail_set — see isOnInitialOrJunk() for the reasoning.
	std::set<StackSlot> initialValues;
	for (auto const& slot: out.initial)
		if (slot.isValue())
			initialValues.insert(slot);

	/// Does this slot either appear on the initial stack, or is it a JUNK
	/// placeholder?
	///
	/// Strictly speaking the shuffler's precondition check also accepts anything
	/// for which canBeFreelyGenerated() holds (literals, junk,
	/// FunctionCallReturnLabel). But in practice the shuffler does not know how
	/// to *push* a literal to satisfy a liveness-only demand — fixTailSlot only
	/// DUPs existing slots or pushes JUNK, so a literal that appears only in
	/// tail_set (or a literal in target_top combined with a non-empty tail_set
	/// that forces it out of reach) loops forever. Until the shuffler grows that
	/// capability we require every non-JUNK slot referenced in target_top or
	/// tail_set to be physically present on the initial stack.
	auto const isOnInitialOrJunk = [&](StackSlot const& _slot)
	{
		if (_slot.isJunk())
			return true;
		if (!_slot.isValue())
			return false; // we don't generate other slot kinds from proto
		return initialValues.contains(_slot);
	};

	// --- 2. target top ---
	// Cap size, then replace unavailable slots with JUNK.
	{
		std::size_t const n = std::min<std::size_t>(
			static_cast<std::size_t>(_input.target_top_size()),
			kMaxTargetTopSize
		);
		out.targetTop.reserve(n);
		for (std::size_t i = 0; i < n; ++i)
		{
			StackSlot slot = protoSlotToStackSlot(_input.target_top(static_cast<int>(i)));
			if (!isOnInitialOrJunk(slot))
				slot = StackSlot::makeJunk();
			out.targetTop.push_back(slot);
		}
	}

	// --- 3. tail set (liveness) ---
	// Rules:
	//   * No JUNK (parseLiveness in the upstream test harness asserts this).
	//   * No literals: liveness is a property of non-constant values, and
	//     literals in a tail set don't correspond to anything the shuffler is
	//     meant to preserve.
	//   * Every value must be on the initial stack (see isOnInitialOrJunk).
	//   * Deduplicate by slot identity.
	StackSlotLiveness::Entries liveCounts;
	{
		std::set<StackSlot> seen;
		std::size_t const n = static_cast<std::size_t>(_input.tail_set_size());
		liveCounts.reserve(std::min<std::size_t>(n, kMaxTargetSize));
		for (std::size_t i = 0; i < n && liveCounts.size() < kMaxTargetSize; ++i)
		{
			StackSlot const slot = protoSlotToStackSlot(_input.tail_set(static_cast<int>(i)));
			if (!slot.isValue())
				continue; // drop JUNK
			if (slot.isLiteralValue())
				continue; // drop literals
			if (!isOnInitialOrJunk(slot))
				continue; // drop slots not physically on the initial stack
			if (!seen.insert(slot).second)
				continue; // dedupe
			liveCounts.emplace_back(slot, /*count=*/1u);
		}
	}
	out.targetTail = StackSlotLiveness{std::move(liveCounts)};

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
