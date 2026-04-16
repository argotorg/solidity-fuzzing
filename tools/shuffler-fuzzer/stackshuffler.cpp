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
 * Outputs "Status: Admissible" (exit 0) or "Status: MaxIterationsReached" (exit 1).
 * With --verbose, also prints the full trace table.
 */

#include "StackShufflerTestCommon.h"

#include <libsolutil/CommonIO.h>

#include <boost/program_options.hpp>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

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

		auto const testConfig = ShuffleTestInput::parse(input);
		if (!testConfig.valid())
		{
			std::cerr << "Error: Could not parse input. Expected format:\n"
				<< "  initial: [<slot>, ...]\n"
				<< "  targetStackTop: [<slot>, ...]\n"
				<< "  targetStackTailSet: {<slot>, ...}   (optional)\n"
				<< "  targetStackSize: <integer>          (optional if no tail set)\n"
				<< "\n"
				<< "Where <slot> is one of: v<N>, phi<N>, lit<N>, JUNK\n";
			return 2;
		}

		auto stackData = *testConfig.initial;
		std::ostringstream traceOutput;
		StackShufflerResult shuffleResult;
		{
			TraceRecorder trace(traceOutput, *testConfig.targetStackTop, testConfig.targetStackTailSet, *testConfig.targetStackSize);
			trace.record("(initial)", *testConfig.initial);
			StackManipulationCallbacks callbacks;
			callbacks.hook = [&](std::string const& op){ trace.record(op, stackData); };
			TestStack stack(stackData, std::move(callbacks));
			shuffleResult = StackShuffler<StackManipulationCallbacks>::shuffle(
				stack,
				*testConfig.targetStackTop,
				testConfig.targetStackTailSet,
				*testConfig.targetStackSize
			);
			// TraceRecorder destructor fires here, writing the trace table to traceOutput
		}

		if (verbose)
			std::cout << traceOutput.str();

		switch (shuffleResult.status)
		{
		case StackShufflerResult::Status::Admissible:
			std::cout << "Status: Admissible" << std::endl;
			return 0;
		case StackShufflerResult::Status::StackTooDeep:
			std::cout << fmt::format("Status: StackTooDeep (culprit: {})", slotToString(shuffleResult.culprit)) << std::endl;
			return 1;
		case StackShufflerResult::Status::MaxIterationsReached:
			std::cout << "Status: MaxIterationsReached" << std::endl;
			return 1;
		case StackShufflerResult::Status::Continue:
			std::cerr << "Error: Unexpected Continue status from shuffle()" << std::endl;
			return 2;
		}
		return 2;
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
