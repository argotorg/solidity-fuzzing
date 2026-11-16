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
/// Projects a ShuffleInput protobuf onto an input satisfying stack::shuffle()'s preconditions, so that
/// precondition asserts in the shuffler are never mistaken for bugs.

#pragma once

#include <tools/ossfuzz/shufflerProto.pb.h>
#include <tools/shuffler-fuzzer/StackShufflerTestCommon.h>

#include <cstddef>
#include <cstdint>

namespace solidity::yul::ssa::shuffler_fuzzer
{

/// Mirrors the upstream property test (test/fuzztest/libyul/StackShufflerPropertyTest.cpp)
inline constexpr std::size_t kMaxStackSize = 40;
/// A small id range makes repeated slots, where the interesting shuffling lives
inline constexpr std::uint32_t kMaxSlotId = 15;
inline constexpr std::uint32_t kMaxCallSiteId = 3;

/// Guarantees: sizes <= kMaxStackSize; at most one return label on `initial` and none in a target that is not
/// a permutation of `initial`; every target slot is producible; spilled slots are variables;
/// reachableDepth in [2, 16].
shuffler_tool::ShuffleCase convertProtoInput(
	::solidity::yul::test::shuffler_fuzzer::ShuffleInput const& _input,
	shuffler_tool::ParsedIdentifierTable& _table
);

}
