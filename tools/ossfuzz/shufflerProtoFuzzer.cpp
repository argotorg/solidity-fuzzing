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
 * libFuzzer harness for the SSA stack shuffler.
 *
 * Flow per fuzzing iteration:
 *   1. Mutator produces a ShuffleInput protobuf.
 *   2. protoToShuffler projects it onto a precondition-satisfying input.
 *   3. We run StackShuffler::shuffle(), which returns the trace of emitted
 *      SWAP/DUP/PUSH/POP/LOAD/STORE ops.
 *   4. Replay those ops from a fresh copy of the initial stack, independently,
 *      and verify:
 *        (a) replay ends in the same data state the shuffler reported, and
 *        (b) that state is admissible with respect to the target.
 *
 * Result handling:
 *   - shuffle() returns a StackShufflerResult; it does not throw for the
 *     expected give-up outcomes.
 *   - Status::StackTooDeep is swallowed — the shuffler is a work in progress
 *     and still legitimately gives up on some configurations. Define
 *     FUZZER_MODE_STACK_TOO_DEEP_IS_BUG at compile time once the shuffler is
 *     expected to handle those.
 *   - Status::MaxIterationsReached (and the never-expected Continue) trips a
 *     solAssert so libFuzzer records it as a crash.
 *   - Precondition violations inside shuffle() still throw (yulAssert); those
 *     indicate a converter bug and escape to libFuzzer as a crash.
 *
 * Oracle: the independent replay + admissibility check catches bugs that the
 * shuffler's own internal `yulAssert(state.admissible())` might miss —
 * specifically, divergence between m_data and the emitted trace, or
 * admissibility logic that disagrees with the spec.
 */

#include <tools/ossfuzz/protoToShuffler.h>
#include <tools/ossfuzz/shufflerProto.pb.h>

#include <libyul/backends/evm/ssa/ShuffleTrace.h>
#include <libyul/backends/evm/ssa/Stack.h>
#include <libyul/backends/evm/ssa/StackShuffler.h>

#include <libsolutil/Assertions.h>
#include <libsolutil/Exceptions.h>

#include <src/libfuzzer/libfuzzer_macro.h>

#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

using namespace solidity;
using namespace solidity::yul;
using namespace solidity::yul::ssa;
using namespace solidity::yul::ssa::shuffler_fuzzer;
using ::solidity::yul::test::shuffler_fuzzer::ShuffleInput;

namespace
{

/// Replays a shuffle trace against a fresh copy of _initial, returning the
/// final stack state. Deliberately does not use ssa::replay() — an independent
/// implementation is what makes this an oracle. Each op is validated against
/// Stack's EVM reachability rules (depth 1..16 for SWAP/DUP, freely-generatable
/// only for PUSH) and any violation aborts via solAssert — these would indicate
/// the shuffler emitted an invalid opcode, which is a bug.
StackData replayOps(StackData const& _initial, ShuffleTrace const& _trace)
{
	static constexpr std::size_t reachable = 16;
	StackData s = _initial;
	for (auto const& op: _trace)
	{
		std::size_t const depth = op.depth;
		switch (op.kind)
		{
		case ShuffleOp::Kind::Swap:
			solAssert(depth >= 1 && depth <= reachable, "shuffler emitted SWAP out of range");
			solAssert(s.size() > depth, "shuffler emitted SWAP deeper than stack");
			std::swap(s[s.size() - 1 - depth], s.back());
			break;
		case ShuffleOp::Kind::Dup:
			solAssert(depth >= 1 && depth <= reachable, "shuffler emitted DUP out of range");
			solAssert(s.size() >= depth, "shuffler emitted DUP deeper than stack");
			s.push_back(s[s.size() - depth]);
			break;
		case ShuffleOp::Kind::Push:
			solAssert(
				canBeFreelyGenerated(op.slot),
				"shuffler PUSHed a slot that cannot be freely generated"
			);
			s.push_back(op.slot);
			break;
		case ShuffleOp::Kind::Load:
			solAssert(op.slot.isValue() && !op.slot.isLiteralValue(), "shuffler LOADed a non-spillable slot");
			s.push_back(op.slot);
			break;
		case ShuffleOp::Kind::Store:
			solAssert(!s.empty() && s.back() == op.slot, "shuffler emitted STORE not consuming its value from the top");
			s.pop_back();
			break;
		case ShuffleOp::Kind::Pop:
			solAssert(!s.empty(), "shuffler emitted POP on empty stack");
			s.pop_back();
			break;
		}
	}
	return s;
}

/// Independent admissibility check — does `_final` satisfy the shuffling target?
/// Mirrors State::admissible() but built from scratch against the public spec
/// so a bug in State::admissible() cannot hide behind its own agreement.
bool isAdmissible(StackData const& _final, ConvertedInput const& _t)
{
	if (_final.size() != _t.targetStackSize)
		return false;

	std::size_t const tailSize = _t.targetStackSize - _t.targetTop.size();

	// Args region: each target arg is either JUNK (admits anything) or must
	// match the stack slot at the same absolute offset.
	for (std::size_t i = 0; i < _t.targetTop.size(); ++i)
	{
		StackSlot const& expected = _t.targetTop[i];
		StackSlot const& actual = _final[tailSize + i];
		if (expected.isJunk())
			continue;
		if (actual != expected)
			return false;
	}

	// Distribution check: sum of required counts across args (non-JUNK) and
	// tail liveness must be covered by counts on the full stack.
	// We rebuild minCount the same way Target does.
	std::vector<std::pair<StackSlot, std::size_t>> minCount;
	auto bumpCount = [&](StackSlot const& _slot) {
		for (auto& [s, c]: minCount)
			if (s == _slot) { ++c; return; }
		minCount.emplace_back(_slot, 1u);
	};
	for (auto const& arg: _t.targetTop)
		if (!arg.isJunk())
			bumpCount(arg);
	for (auto const& [slot, _count]: _t.targetTail)
		bumpCount(slot);

	for (auto const& [slot, need]: minCount)
	{
		std::size_t have = 0;
		for (auto const& s: _final)
			if (s == slot)
				++have;
		if (have < need)
			return false;
	}
	return true;
}

/// Serialise a ConvertedInput to the .stack file format understood by the
/// standalone `stackshuffler` CLI tool, so crashes can be replayed via:
///   stackshuffler --verbose <dumped.stack>
std::string toStackFileFormat(ConvertedInput const& _t)
{
	std::ostringstream out;

	out << "initial: " << stackToString(_t.initial) << "\n";
	out << "targetStackTop: " << stackToString(_t.targetTop) << "\n";

	out << "targetStackTailSet: {";
	bool first = true;
	for (auto const& [slot, _count]: _t.targetTail)
	{
		if (!first)
			out << ", ";
		first = false;
		out << slotToString(slot);
	}
	out << "}\n";

	out << "targetStackSize: " << _t.targetStackSize << "\n";
	return out.str();
}

} // anonymous namespace

DEFINE_PROTO_FUZZER(ShuffleInput const& _input)
{
	ConvertedInput converted = convertProtoInput(_input);

	// Dump the post-conversion shuffler input to a .stack file for reproduction.
	// Usage:
	//   PROTO_FUZZER_DUMP_PATH=x.stack ./shuffler_proto_ossfuzz crash-XXXX
	//   ./stackshuffler --verbose x.stack
	if (char const* dumpPath = std::getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		std::string const dumped = toStackFileFormat(converted);
		std::ofstream of(dumpPath);
		of.write(dumped.data(), static_cast<std::streamsize>(dumped.size()));
	}

	// The converter already enforces these, but double-check cheaply — a bug
	// in the converter that violates them would mask real shuffler bugs as
	// "precondition yulAssert" trips.
	if (converted.targetStackSize < converted.targetTop.size())
		return;
	if (converted.targetTail.size() > converted.targetStackSize - converted.targetTop.size())
		return;

	StackData stackData = converted.initial;

	// shuffle() returns a status rather than throwing for the expected give-up
	// outcomes. A Status::StackTooDeep is an honest give-up and is silenced by
	// default; MaxIterationsReached (and the never-expected Continue) is a bug.
	// Precondition violations inside shuffle() still throw and escape as crashes.
	StackShufflerResult const result = StackShuffler::shuffle(
		stackData,
		converted.targetTop,
		converted.targetTail,
		converted.targetStackSize
	);
	if (result.status == StackShufflerResult::Status::StackTooDeep)
	{
#ifdef FUZZER_MODE_STACK_TOO_DEEP_IS_BUG
		solAssert(false, "shuffler gave up: stack too deep");
#else
		return; // honest give-up: ignore for now
#endif
	}
	solAssert(
		result.status == StackShufflerResult::Status::Admissible,
		"shuffle() returned a non-admissible, non-stack-too-deep status (e.g. max iterations reached)"
	);

	// --- Oracle 1: replay the emitted opcodes and check we end up where the
	//     shuffler's internal m_data ended up. Catches any drift between the
	//     recorded trace and Stack's internal bookkeeping.
	StackData replayed = replayOps(converted.initial, result.trace);
	solAssert(
		replayed == stackData,
		"Replay of shuffler-emitted opcodes diverges from shuffler's internal stack"
	);

	// --- Oracle 2: check the state is actually admissible against the target,
	//     independent of the shuffler's own admissibility check.
	solAssert(
		isAdmissible(stackData, converted),
		"Shuffler reported success but resulting stack is not admissible"
	);
}
