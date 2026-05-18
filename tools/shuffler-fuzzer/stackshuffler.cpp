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
 * Standalone tool for running the SSA stack shuffler on .stack test files.
 *
 * Usage:
 *   stackshuffler [--verbose] <file.stack>
 *   stackshuffler [--verbose] -          (read from stdin)
 *
 * Prints "Status: <Admissible|StackTooDeep|MaxIterationsReached>" and exits 0 for
 * Admissible, 1 otherwise. With --verbose, also prints the full trace table.
 */

#include "StackShufflerTestCommon.h"

#include <libyul/Exceptions.h>

#include <libsolutil/CommonIO.h>

#include <boost/program_options.hpp>

#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace po = boost::program_options;

using namespace solidity;
using namespace solidity::yul;
using namespace solidity::yul::ssa;
using namespace solidity::yul::ssa::shuffler_tool;
using namespace solidity::util;

namespace
{

/// Strip everything after "// ----" (the expected-output delimiter in .stack files)
std::string stripExpectations(std::string const& _source)
{
	auto const pos = _source.find("// ----");
	if (pos != std::string::npos)
		return _source.substr(0, pos);
	return _source;
}

} // anonymous namespace

int main(int argc, char** argv)
{
	try
	{
		bool verbose = false;
		po::options_description options(
			R"(stackshuffler - SSA stack shuffler test tool.
Usage: stackshuffler [Options] <file.stack>
Reads a .stack file and runs the stack shuffler on it.
If <file> is -, input is read from stdin.

Allowed options)",
			po::options_description::m_default_line_length,
			po::options_description::m_default_line_length - 23);
		options.add_options()
			(
				"input-file",
				po::value<std::string>(),
				"input .stack file"
			)
			(
				"verbose,v",
				po::bool_switch(&verbose)->default_value(false),
				"print the full trace table"
			)
			("help,h", "Show this help screen.");

		po::positional_options_description filesPositions;
		filesPositions.add("input-file", 1);

		po::variables_map arguments;
		po::command_line_parser cmdLineParser(argc, argv);
		cmdLineParser.options(options).positional(filesPositions);
		po::store(cmdLineParser.run(), arguments);
		po::notify(arguments);

		if (arguments.count("help") || !arguments.count("input-file"))
		{
			std::cout << options;
			return arguments.count("help") ? 0 : 1;
		}

		std::string input;
		std::string const filename = arguments["input-file"].as<std::string>();
		if (filename == "-")
			input = readUntilEnd(std::cin);
		else
			input = readFileAsString(filename);

		input = stripExpectations(input);

		ParsedIdentifierTable table;
		auto const testConfig = ShuffleTestInput::parse(table, input);
		if (!testConfig.valid())
		{
			std::cerr << "Error: Could not parse input. Expected format:\n"
				<< "  initial: [<slot>, ...]\n"
				<< "  targetStackTop: [<slot>, ...]\n"
				<< "  targetStackTailSet: {<slot>, ...}   (optional)\n"
				<< "  targetStackSize: <integer>          (optional if no tail set)\n"
				<< "  allowSpilling: <true|false>         (optional)\n"
				<< "  initialSpilledSet: {<slot>, ...}    (optional)\n"
				<< "\n"
				<< "Where <slot> is one of: v<N>, phi<N>, lit<N>, JUNK, ReturnLabel[<N>]\n";
			return 2;
		}

		auto stackData = *testConfig.initial;
		std::ostringstream traceOutput;
		StackShufflerResult shuffleResult;
		SpilledVariables spillSet = testConfig.initialSpilledSet;
		// Tracks the kind of each spilled value (for rendering).
		std::vector<StackSlot> spilledSlotList = testConfig.initialSpilledSetSlots;

		// When spilling is allowed, run the shuffler repeatedly without recording to determine
		// the final spill set. Each iteration starts from the initial stack and adds the culprit
		// of a recoverable StackTooDeep to the spill set.
		if (testConfig.allowSpilling)
			while (true)
			{
				auto scratch = *testConfig.initial;
				Stack<> stack(scratch, {});
				auto const result = StackShuffler<NoOpStackManipulationCallbacks>::shuffle(
					stack,
					*testConfig.targetStackTop,
					testConfig.targetStackTailSet,
					*testConfig.targetStackSize,
					&spillSet
				);
				if (result.status != StackShufflerResult::Status::StackTooDeep)
					break;
				spillSet.spill(result.culprit.value());
				spilledSlotList.push_back(result.culprit);
			}

		// Final shuffle with the (possibly pre-populated) spill set, recording the trace.
		{
			TraceRecorder trace(
				traceOutput,
				table,
				*testConfig.targetStackTop,
				testConfig.targetStackTailSetSlots,
				*testConfig.targetStackSize,
				spillSet
			);
			trace.record("(initial)", *testConfig.initial);
			TestStack stack(stackData, {.table = table, .hook = [&](std::string const& op)
			{
				trace.record(op, stackData);
			}});
			shuffleResult = StackShuffler<StackManipulationCallbacks>::shuffle(
				stack,
				*testConfig.targetStackTop,
				testConfig.targetStackTailSet,
				*testConfig.targetStackSize,
				&spillSet
			);
			if (shuffleResult.status == StackShufflerResult::Status::MaxIterationsReached)
				trace.truncate(30);
			// TraceRecorder destructor fires here, writing the trace table to traceOutput
		}

		if (verbose)
			std::cout << traceOutput.str();

		switch (shuffleResult.status)
		{
		case StackShufflerResult::Status::Admissible:
			std::cout << "Status: Admissible" << std::endl;
			break;
		case StackShufflerResult::Status::StackTooDeep:
			std::cout << fmt::format("Status: StackTooDeep (culprit: {})", table.render(shuffleResult.culprit)) << std::endl;
			break;
		case StackShufflerResult::Status::MaxIterationsReached:
			std::cout << "Status: MaxIterationsReached" << std::endl;
			break;
		case StackShufflerResult::Status::Continue:
			yulAssert(false, "Unexpected Continue status from shuffle()");
		}
		if (testConfig.allowSpilling)
			std::cout << fmt::format(
				"Spilled: {{{}}}",
				fmt::join(
					spilledSlotList | ranges::views::transform([&](StackSlot const& _slot) { return table.render(_slot); }),
					", "
				)
			) << std::endl;

		return shuffleResult.status == StackShufflerResult::Status::Admissible ? 0 : 1;
	}
	catch (po::error const& _exception)
	{
		std::cerr << _exception.what() << std::endl;
		return 2;
	}
	catch (std::exception const& _exception)
	{
		std::cerr << "Error: " << _exception.what() << std::endl;
		return 2;
	}
}
