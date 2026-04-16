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
 * Converts a fuzzer-generated ShuffleInput protobuf message into shuffler-ready
 * inputs (initial stack, target top args, target tail set, target stack size).
 *
 * The converter is responsible for projecting arbitrary protobuf mutations onto
 * the subset that satisfies StackShuffler::shuffle()'s preconditions — the
 * shuffler itself is full of precondition assertions and we don't want those
 * to be mistaken for bugs by the fuzzer.
 */

#pragma once

#include <libyul/backends/evm/ssa/LivenessAnalysis.h>
#include <libyul/backends/evm/ssa/Stack.h>

#include <tools/ossfuzz/shufflerProto.pb.h>

#include <cstddef>

namespace solidity::yul::ssa::shuffler_fuzzer
{

using ::solidity::yul::ssa::LivenessAnalysis;
using ::solidity::yul::ssa::StackData;

/// Upper bound on the initial stack size accepted from the fuzzer input.
/// The shuffler has a hard-coded reachableStackDepth of 16 and shrinking only
/// works so far, so very tall initial stacks just produce stack-too-deep
/// outcomes which aren't interesting until the shuffler grows past that.
inline constexpr std::size_t kMaxInitialSize = 32;
/// Upper bound on the target top (args) size.
inline constexpr std::size_t kMaxTargetTopSize = 24;
/// Upper bound on the total target stack size (target_top + tail).
/// Larger targets mostly produce honest stack-too-deep results.
inline constexpr std::size_t kMaxTargetSize = 32;
/// Upper bound on slot id values — small range produces more slot collisions,
/// which is where the interesting shuffling logic lives (duplicates, etc.).
inline constexpr std::uint32_t kMaxSlotId = 15;

/// Result of converting a proto input into shuffler inputs.
/// All preconditions of StackShuffler::shuffle() are satisfied.
struct ConvertedInput
{
	StackData initial;
	StackData targetTop;
	LivenessAnalysis::LivenessData targetTail;
	std::size_t targetStackSize = 0;
};

/// Convert a protobuf ShuffleInput into a ConvertedInput.
///
/// Guarantees on the returned value:
///  - initial.size() <= kMaxInitialSize
///  - targetTop.size() <= kMaxTargetTopSize
///  - targetStackSize <= kMaxTargetSize
///  - targetStackSize >= targetTop.size()
///  - targetTail.size() <= targetStackSize - targetTop.size()
///  - every V/PHI slot in targetTop appears in initial
///    (others are replaced with JUNK)
///  - every value id in targetTail either appears in initial or is freely
///    generatable (i.e., a Literal). No JUNK / Variable-or-Phi-not-in-initial.
///  - targetTail has at most one entry per value id (deduplicated)
///  - no junk in targetTail
ConvertedInput convertProtoInput(
	::solidity::yul::test::shuffler_fuzzer::ShuffleInput const& _input
);

}
