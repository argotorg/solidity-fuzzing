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

/// ICE-hunter fuzzer — looks for `InternalCompilerError`, `solAssert`
/// failures, and other compiler-internal crashes on any Solidity source
/// emitted by the sol2Proto grammar. Deliberately does *not* execute code;
/// the goal is to fuzz the frontend (parser, name resolver, type checker,
/// AST analysis). Iteration throughput is much higher than the
/// execution-differential fuzzers because there is no EVM deploy/run path.
///
/// Only exceptions that denote *known non-bugs* are caught (unimplemented
/// features, stack-too-deep). Everything else — notably `InternalCompilerError`
/// and any boost assertion failure — escapes so libFuzzer records a crash.

#include <tools/ossfuzz/protoToSol2.h>
#include <tools/ossfuzz/sol2Proto.pb.h>

#include <libsolidity/interface/CompilerStack.h>
#include <libsolidity/interface/OptimiserSettings.h>

#include <libevmasm/Exceptions.h>
#include <liblangutil/EVMVersion.h>
#include <liblangutil/Exceptions.h>

#include <libyul/YulString.h>

#include <src/libfuzzer/libfuzzer_macro.h>

#include <cstdlib>
#include <fstream>
#include <string>

using namespace solidity;
using namespace solidity::frontend;
using namespace solidity::test::sol2protofuzzer;

DEFINE_PROTO_FUZZER(Program const& _input)
{
	yul::YulStringRepository::reset();

	ProtoConverter converter;
	std::string source = converter.protoToSolidity(_input);

	if (char const* dumpPath = std::getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		std::ofstream of(dumpPath);
		of.write(source.data(), static_cast<std::streamsize>(source.size()));
	}

	// Bound single-compile time. The frontend path we care about is reached
	// well before this cap; enormous sources mostly burn cycles in parsing.
	if (source.size() > 8000)
		return;

	CompilerStack compiler;
	compiler.setSources({{"test.sol", source}});
	compiler.setEVMVersion(langutil::EVMVersion{});
	compiler.setViaIR(_input.via_ir());
	compiler.setOptimiserSettings(
		_input.optimize() ? OptimiserSettings::standard() : OptimiserSettings::minimal()
	);
	compiler.setMetadataFormat(CompilerStack::MetadataFormat::NoMetadata);

	try
	{
		compiler.compile();
	}
	// Known non-bugs — matches the allowlist in test/tools/fuzzer_common.cpp.
	// Every other exception type (notably `langutil::InternalCompilerError`
	// and any boost assertion wrapper) is intentionally left uncaught so
	// libFuzzer treats it as a crash.
	catch (langutil::UnimplementedFeatureError const&)
	{
	}
	catch (langutil::StackTooDeepError const&)
	{
	}
	catch (evmasm::StackTooDeepException const&)
	{
	}
}
