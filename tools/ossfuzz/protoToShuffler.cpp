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

#include <algorithm>
#include <numeric>
#include <utility>
#include <vector>

using namespace solidity::yul::ssa;
using namespace solidity::yul::ssa::shuffler_tool;
using ProtoSlot = ::solidity::yul::test::shuffler_fuzzer::Slot;
using ProtoInput = ::solidity::yul::test::shuffler_fuzzer::ShuffleInput;

namespace solidity::yul::ssa::shuffler_fuzzer
{

ShuffleCase convertProtoInput(ProtoInput const& _input, ParsedIdentifierTable& _table)
{
	auto const toSlot = [&](ProtoSlot const& _slot) -> StackSlot {
		std::uint32_t const id = _slot.id() % (kMaxSlotId + 1);
		switch (_slot.kind())
		{
		case ProtoSlot::V: return parseSlot(_table, fmt::format("v{}", id));
		case ProtoSlot::PHI: return parseSlot(_table, fmt::format("phi{}", id));
		case ProtoSlot::LIT: return parseSlot(_table, fmt::format("lit{}", id));
		case ProtoSlot::CALL_RET: return StackSlot::makeFunctionCallReturnLabel(id % (kMaxCallSiteId + 1));
		case ProtoSlot::FUNC_RET: return StackSlot::makeFunctionReturnLabel(0);
		default: return StackSlot::makeJunk();
		}
	};
	auto const capped = [](int _size) { return std::min<std::size_t>(static_cast<std::size_t>(_size), kMaxStackSize); };

	ShuffleCase out;
	out.allowSpilling = _input.allow_spilling();
	std::uint32_t const depth = _input.reachable_depth() % (reachableStackDepth + 1);
	out.reachableDepth = depth < 2 ? reachableStackDepth : depth;

	// A second return label is not a state a function can be in.
	bool haveReturnLabel = false;
	for (std::size_t i = 0; i < capped(_input.initial_size()); ++i)
	{
		StackSlot slot = toSlot(_input.initial(static_cast<int>(i)));
		if (slot.isFunctionReturnLabel() && std::exchange(haveReturnLabel, true))
			slot = StackSlot::makeJunk();
		out.initial.push_back(slot);
	}

	for (int i = 0; i < _input.spilled_size() && out.spilled.size() < kMaxSlotId + 1; ++i)
	{
		StackSlot const slot = toSlot(_input.spilled(i));
		if (slot.isVariable() && std::find(out.spilled.begin(), out.spilled.end(), slot) == out.spilled.end())
			out.spilled.push_back(slot);
	}

	if (_input.target_mode() == ProtoInput::PERMUTED)
	{
		std::vector<std::size_t> order(out.initial.size());
		std::iota(order.begin(), order.end(), 0u);
		for (std::size_t i = order.size(); i > 1 && static_cast<int>(order.size() - i) < _input.permutation_size(); --i)
			std::swap(order[i - 1], order[_input.permutation(static_cast<int>(order.size() - i)) % i]);
		for (std::size_t i = 0; i < order.size(); ++i)
		{
			StackSlot slot = out.initial[order[i]];
			bool const masked = static_cast<int>(i) < _input.target_size() &&
				_input.target(static_cast<int>(i)).kind() == ProtoSlot::JUNK;
			if (masked && !slot.isFunctionReturnLabel())
				slot = StackSlot::makeJunk();
			out.target.push_back(slot);
		}
	}
	else
	{
		spill::SpillSet const spills = out.spillSet();
		for (std::size_t i = 0; i < capped(_input.target_size()); ++i)
		{
			StackSlot slot = toSlot(_input.target(static_cast<int>(i)));
			bool const producible = canBeFreelyGenerated(slot) ||
				(slot.isVariable() && (spills.isSpilled(slot) ||
					std::find(out.initial.begin(), out.initial.end(), slot) != out.initial.end()));
			if (!producible)
				slot = StackSlot::makeJunk();
			out.target.push_back(slot);
		}
	}
	return out;
}

}
