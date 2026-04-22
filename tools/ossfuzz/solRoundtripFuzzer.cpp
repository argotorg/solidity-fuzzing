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

/// Identity-oracle fuzzer for Solidity primitive types. Each input proto
/// is a list of probes, each probe is (type, op, seed). The generated
/// test() performs each probe's identity operation and sets bit i of the
/// returned bitmask iff probe i's identity does not hold. The harness
/// asserts the return is zero.
///
/// Why it exists: identities like `abi.decode(abi.encode(v), (T)) == v`,
/// `storage→memory→storage == v`, and `delete x; x == 0` must hold
/// independent of codegen and optimizer, and bugs that violate them often
/// violate both legacy and IR paths identically — so differential fuzzers
/// miss them. The in-contract oracle here catches exactly those.

#include <tools/ossfuzz/protoToSolRoundtrip.h>
#include <tools/ossfuzz/solRoundtripProto.pb.h>
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

#include <cstdlib>
#include <fstream>
#include <string>

static evmc::VM evmone = evmc::VM{evmc_create_evmone()};

using namespace solidity;
using namespace solidity::frontend;
using namespace solidity::test;
using namespace solidity::test::fuzzer;
using namespace solidity::test::solroundtrip;

static constexpr int64_t s_gasLimit = 2'000'000;

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

	// No probes → nothing to check. libFuzzer will mutate toward probes.
	if (converter.probeCount() == 0)
		return;

	EVMHost host(langutil::EVMVersion::current(), evmone);
	host.accounts[host.tx_context.tx_origin].set_balance(0xffffffff);

	OptimiserSettings settings =
		_input.optimize() ? OptimiserSettings::standard() : OptimiserSettings::minimal();

	StringMap sources({{"test.sol", source}});
	CompilerInput cInput(
		langutil::EVMVersion::current(),
		sources,
		"C",
		settings,
		{},
		false,
		_input.via_ir()
	);
	EvmoneUtility evmoneUtil(host, cInput, "C", "", "test()", s_gasLimit);

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

	if (result.status_code != EVMC_SUCCESS)
		return;
	if (result.output_size != 32)
		return;

	bool anyNonZero = false;
	for (size_t i = 0; i < 32; i++)
		if (result.output_data[i] != 0)
		{
			anyNonZero = true;
			break;
		}
	solAssert(
		!anyNonZero,
		"sol_roundtrip_ossfuzz: identity oracle failed — "
		"one of abi-roundtrip / storage-mem-roundtrip / delete-default / "
		"cast-ladder did not hold"
	);
}
