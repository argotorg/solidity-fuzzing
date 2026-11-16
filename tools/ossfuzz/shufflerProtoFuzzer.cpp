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
/// AFL++/LPM harness for the SSA stack shuffler (stack::shuffle). The oracle (checkShuffle in
/// StackShufflerTestCommon.h) re-checks the result independently of the shuffler's own helpers: completeness
/// when spilling is allowed, spill-set monotonicity, op validity and depth bounds, replay == reported stack,
/// positional match with the target, and the sourceOf plan. Any exception from shuffle() is a bug too: the
/// converter guarantees its preconditions.
///
/// Reproduce: PROTO_FUZZER_DUMP_PATH=x.stack ./shuffler_proto_ossfuzz <crash>; stackshuffler -v x.stack

#include <tools/ossfuzz/protoToShuffler.h>
#include <tools/ossfuzz/shufflerProto.pb.h>

#include <libsolutil/Assertions.h>
#include <libsolutil/Exceptions.h>

#include <src/libfuzzer/libfuzzer_macro.h>

#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

using namespace solidity;
using namespace solidity::yul::ssa;
using namespace solidity::yul::ssa::shuffler_tool;
using ::solidity::yul::test::shuffler_fuzzer::ShuffleInput;

DEFINE_PROTO_FUZZER(ShuffleInput const& _input)
{
	ParsedIdentifierTable table;
	ShuffleCase const shuffleCase = shuffler_fuzzer::convertProtoInput(_input, table);

	if (char const* dumpPath = std::getenv("PROTO_FUZZER_DUMP_PATH"))
		std::ofstream(dumpPath) << shuffleCase.format(table);

	solAssert(targetProducible(shuffleCase), "converter produced a target with an unproducible slot");

	StackData shuffled = shuffleCase.initial;
	spill::SpillSet spills = shuffleCase.spillSet();
	stack::ShuffleResult const result = stack::shuffle(
		shuffled, shuffleCase.target, spills, shuffleCase.allowSpilling, shuffleCase.reachableDepth
	);
#ifdef FUZZER_MODE_STACK_TOO_DEEP_IS_BUG
	solAssert(result.status == stack::ShuffleResult::Status::Admissible, "shuffler gave up: stack too deep");
#endif

	std::vector<std::string> const violations = checkShuffle(table, shuffleCase, result, shuffled, spills);
	solAssert(violations.empty(), "Stack shuffler spec violation: " + violations.front());
}
