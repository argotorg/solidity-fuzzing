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

/// Targeted fuzzer for report #1392: storage-to-storage struct assignment of
/// the form `root = root.children[i]` corrupts fields that sit after the
/// recursive array, because the compiler clears the array (which holds the
/// source struct) before finishing the member copy. Legacy and IR codegens
/// both carry the bug, so differential fuzzers comparing the two paths see
/// matching wrong outputs and miss it. This harness uses an in-contract
/// oracle instead: the generated test() returns a bitmask of fields whose
/// post-copy value differs from the pre-copy snapshot. Any nonzero return
/// value is a bug.

#include <tools/ossfuzz/protoToSolRecStructAlias.h>
#include <tools/ossfuzz/solRecStructAliasProto.pb.h>
#include <tools/ossfuzz/SolidityEvmoneInterface.h>

#include <tools/common/EVMHost.h>

#include <libevmasm/Exceptions.h>
#include <liblangutil/EVMVersion.h>
#include <liblangutil/Exceptions.h>

#include <libyul/Exceptions.h>
#include <libyul/YulString.h>

#include <libsolidity/interface/OptimiserSettings.h>

#include <evmone/evmone.h>
#include <src/libfuzzer/libfuzzer_macro.h>

#include <cstring>
#include <cstdlib>
#include <fstream>
#include <string>

static evmc::VM evmone = evmc::VM{evmc_create_evmone()};

using namespace solidity;
using namespace solidity::frontend;
using namespace solidity::test;
using namespace solidity::test::fuzzer;
using namespace solidity::test::solrecstructalias;

/// Gas limit for the single test() call. Generated programs are tiny
/// (one struct, one push loop bounded by kMaxPushes, one copy, a handful
/// of compares); 1M is plenty.
static constexpr int64_t s_gasLimit = 1'000'000;

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

	// If the proto-selected struct has no primitive fields, the test can
	// never report a bug (mask stays zero). Skip — libFuzzer will mutate.
	unsigned const primCount = converter.primitiveFieldCount();
	if (primCount == 0)
		return;

	EVMHost host(langutil::EVMVersion::current(), evmone);
	host.accounts[host.tx_context.tx_origin].set_balance(0xffffffff);

	OptimiserSettings settings =
		_input.optimize() ? OptimiserSettings::standard() : OptimiserSettings::minimal();

	StringMap sources({{"test.sol", source}});
	CompilerInput cInput(
		langutil::EVMVersion::current(),
		sources,
		/*contractName=*/"C",
		settings,
		/*libraryAddresses=*/{},
		/*debugFailure=*/false,
		/*viaIR=*/_input.via_ir()
	);
	EvmoneUtility evmoneUtil(
		host,
		cInput,
		/*contractName=*/"C",
		/*libraryName=*/"",
		/*methodName=*/"test()",
		s_gasLimit
	);

	// Swallow known non-bug exceptions. solAssert (InternalCompilerError)
	// from the oracle check below must NOT be caught — that's how libFuzzer
	// learns a bug was found.
	evmc::Result result{EVMC_INTERNAL_ERROR};
	try
	{
		result = evmoneUtil.compileDeployAndExecute();
	}
	catch (langutil::InternalCompilerError const&) { return; }
	catch (langutil::UnimplementedFeatureError const&) { return; }
	catch (langutil::StackTooDeepError const&) { return; }
	catch (evmasm::StackTooDeepException const&) { return; }
	catch (yul::YulAssertion const&) { return; }
	catch (yul::YulException const&) { return; }

	// Deployment or call failure: not our target. Skip.
	if (result.status_code != EVMC_SUCCESS)
		return;

	// The ABI return of `function test() external returns (uint256)` is a
	// single 32-byte word. Anything else means the contract didn't return
	// what we expect — not our bug shape, skip.
	if (result.output_size != 32)
		return;

	// The oracle: the generated contract returns a bitmask over the
	// primCount primitive fields. Any nonzero bit means post-copy value
	// != pre-copy snapshot for that field — exactly the report #1392
	// corruption. solAssert throws InternalCompilerError, which libFuzzer
	// records as a crash.
	bool anyNonZero = false;
	for (size_t i = 0; i < 32; i++)
		if (result.output_data[i] != 0)
		{
			anyNonZero = true;
			break;
		}
	solAssert(
		!anyNonZero,
		"sol_recstruct_alias_ossfuzz: post-copy mismatch in recursive "
		"storage struct assignment (report #1392 shape)"
	);
}
