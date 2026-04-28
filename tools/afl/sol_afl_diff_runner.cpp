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
 * AFL++ harness for differential Solidity fuzzing against EVMOne.
 *
 * Reads a Solidity source from argv[1] (file path) or stdin, then for each
 * of two optimiser settings ({minimal, standard}):
 *   1. compiles the last contract in the source
 *   2. deploys it
 *   3. calls it with calldata bytes derived deterministically from the source
 *      (keccak256 of the source — gives different shapes per input without
 *       AFL having to mutate the call boundary itself)
 *   4. captures status / output / logs / storage / transient storage
 * On any cross-config mismatch, solAssert throws InternalCompilerError; we
 * deliberately let it propagate so std::terminate raises SIGABRT and AFL++
 * records a crash.
 *
 * Designed to be driven by afl-fuzz with a corpus of real-world Solidity
 * contracts plus the solidity submodule's test suite. Works with afl-ts
 * (https://github.com/nowarp/afl-ts) as a custom mutator.
 *
 * Note vs sol_proto_ossfuzz_evmone: that fuzzer emits contract C { test(); }
 * and looks up the test() selector by name. We can't assume corpus entries
 * have a function called test() (most don't), so we send raw calldata bytes
 * to the deployed contract and let solc's dispatcher route them. Mismatched
 * selectors fall through to fallback() / receive() / revert — still useful
 * for differential testing.
 */

#include <tools/ossfuzz/SolidityEvmoneInterface.h>
#include <tools/ossfuzz/FuzzerDiffCommon.h>
#include <tools/common/EVMHost.h>

#include <libevmasm/Exceptions.h>
#include <liblangutil/Exceptions.h>
#include <libyul/Exceptions.h>
#include <libyul/YulString.h>
#include <libsolutil/Keccak256.h>
#include <libsolutil/CommonData.h>
#include <libsolutil/CommonIO.h>

#include <cstring>
#include <iostream>
#include <sstream>
#include <string>

using namespace solidity;
using namespace solidity::frontend;
using namespace solidity::test;
using namespace solidity::test::fuzzer;
using namespace solidity::util;

/// Lazily resolved on first use via dlopen — same approach as sol_debug_runner.
/// Path is RPATH-baked into the executable (see CMakeLists.txt), so neither
/// LD_LIBRARY_PATH nor an absolute path is needed at runtime.
static evmc::VM& evmone() { return EVMHost::getVM("libevmone.so"); }

/// Matches the proto fuzzer; high enough to deploy and run small contracts,
/// low enough to keep iterations fast.
static constexpr int64_t s_gasLimit = 1000000;

/// Bigger than the proto fuzzer's 3 KB cap because real-world corpus entries
/// (OpenZeppelin etc.) routinely exceed 3 KB. afl-ts splices keep growing the
/// input, so we still need *some* ceiling — 16 KB is a reasonable trade-off.
static constexpr size_t s_maxSourceBytes = 16 * 1024;

/// Indicates "skip this run" — caller compares two skips as equal so the
/// outer differential bails cleanly.
static RunResult skip()
{
	return RunResult{evmc::Result{EVMC_INTERNAL_ERROR}, false, {}, {}, {}, {}};
}

/// Compile the source, deploy the resulting bytecode, send `_calldata` to
/// the deployment. Capture state for the differential check.
static RunResult runOnce(
	langutil::EVMVersion _version,
	StringMap const& _source,
	OptimiserSettings _optimiserSettings,
	bool _viaIR,
	bytes const& _calldata
)
{
	// Empty contractName lets SolidityCompilationFramework fall back to
	// lastContractName(), which is what we want for arbitrary corpus entries
	// where we can't predict the contract name.
	CompilerInput cInput(
		_version,
		_source,
		/*contractName=*/"",
		_optimiserSettings,
		{},
		/*debugFailure=*/false,
		_viaIR
	);

	// Same exception-swallowing list as the proto fuzzer: known non-bugs and
	// cases that belong to sol_ice_ossfuzz. Compilation does most of the work
	// where these can fire. solAssert in the diff-checking code below also
	// throws InternalCompilerError, but it never reaches THIS scope because
	// the diff check runs in main() after we return — so there is no risk of
	// swallowing a real diff here.
	std::optional<CompilerOutput> compOut;
	try
	{
		SolidityCompilationFramework compiler(cInput);
		compOut = compiler.compileContract();
	}
	catch (langutil::InternalCompilerError const&)     { return skip(); }
	catch (langutil::UnimplementedFeatureError const&) { return skip(); }
	catch (langutil::StackTooDeepError const&)         { return skip(); }
	catch (evmasm::StackTooDeepException const&)       { return skip(); }
	catch (yul::YulAssertion const&)                   { return skip(); }
	catch (yul::YulException const&)                   { return skip(); }

	if (!compOut.has_value() || compOut->byteCode.empty())
		return skip();

	EVMHost host(_version, evmone());
	host.accounts[host.tx_context.tx_origin].set_balance(0xffffffff);

	// Deploy.
	evmc_message createMsg = EvmoneUtility::initializeMessage(compOut->byteCode, s_gasLimit);
	createMsg.kind = EVMC_CREATE;
	evmc::Result createResult = host.call(createMsg);
	if (createResult.status_code != EVMC_SUCCESS)
		return skip();

	// Call with raw calldata. First 4 bytes act as selector if they happen
	// to match a public function; otherwise solc's dispatcher falls through
	// to fallback/receive or reverts. Either outcome is a valid differential
	// observation as long as both configs agree.
	evmc_message callMsg = EvmoneUtility::initializeMessage(_calldata, s_gasLimit);
	callMsg.kind = EVMC_CALL;
	callMsg.recipient = createResult.create_address;
	callMsg.code_address = createResult.create_address;
	evmc::Result execResult = host.call(callMsg);

	std::vector<evmc::MockedHost::log_record> logs(host.recorded_logs.begin(), host.recorded_logs.end());

	std::map<evmc::address, StorageMap> storage;
	for (auto const& [addr, account] : host.accounts)
		if (!account.storage.empty())
			storage[addr] = account.storage;

	std::map<evmc::address, TransientStorageMap> transientStorage;
	for (auto const& [addr, account] : host.accounts)
		if (!account.transient_storage.empty())
			transientStorage[addr] = account.transient_storage;

	return RunResult{
		std::move(execResult),
		host.m_subCallOutOfGas,
		std::move(logs),
		std::move(storage),
		std::move(transientStorage),
		host.m_contractCreationOrder
	};
}

/// 32 bytes of calldata derived from the source content. Different inputs
/// exercise different selectors / arguments without AFL having to mutate the
/// call boundary itself.
static bytes deriveCalldata(std::string const& _source)
{
	return keccak256(_source).asBytes();
}

static std::string readSource(int _argc, char** _argv)
{
	if (_argc >= 2)
		return readFileAsString(_argv[1]);
	std::ostringstream ss;
	ss << std::cin.rdbuf();
	return ss.str();
}

int main(int argc, char** argv)
{
	yul::YulStringRepository::reset();

	std::string source = readSource(argc, argv);
	if (source.empty() || source.size() > s_maxSourceBytes)
		return 0;

	langutil::EVMVersion version = langutil::EVMVersion::current();
	StringMap sources({{"test.sol", source}});
	bytes const calldata = deriveCalldata(source);

	OptimiserSettings settingsA = OptimiserSettings::minimal();
	OptimiserSettings settingsB = OptimiserSettings::standard();

	// No outer try/catch on purpose. runOnce already swallows the known
	// non-bug exceptions; any InternalCompilerError reaching this scope —
	// including the one solAssert throws on a diff — must propagate so AFL
	// records a SIGABRT crash via terminate().
	bool const viaIR = false;
	auto runA = runOnce(version, sources, settingsA, viaIR, calldata);
	auto runB = runOnce(version, sources, settingsB, viaIR, calldata);

	// Skip on deployment failure (matches proto fuzzer behavior).
	if (runA.result.status_code != EVMC_SUCCESS && runA.result.status_code != EVMC_REVERT) return 0;
	if (runB.result.status_code != EVMC_SUCCESS && runB.result.status_code != EVMC_REVERT) return 0;

	// Skip on sub-call OOG — legitimate cross-optimisation difference.
	if (runA.subCallOutOfGas || runB.subCallOutOfGas) return 0;

	std::string const label = "Sol AFL diff fuzzer";

	solAssert(
		runA.result.status_code == runB.result.status_code,
		label + ": status code differs (A=" + std::to_string(runA.result.status_code) +
			" B=" + std::to_string(runB.result.status_code) + ")"
	);

	if (runA.result.status_code == EVMC_SUCCESS && runB.result.status_code == EVMC_SUCCESS)
	{
		solAssert(
			runA.result.output_size == runB.result.output_size &&
			std::memcmp(runA.result.output_data, runB.result.output_data, runA.result.output_size) == 0,
			label + ": output differs"
		);
		solAssert(logsEqual(runA.logs, runB.logs), label + ": logs differ");
		solAssert(
			storageEqual(runA.storage, runA.contractCreationOrder, runB.storage, runB.contractCreationOrder),
			label + ": storage differs"
		);
		solAssert(
			transientStorageEqual(runA.transientStorage, runA.contractCreationOrder, runB.transientStorage, runB.contractCreationOrder),
			label + ": transient storage differs"
		);
	}

	if (runA.result.status_code == EVMC_REVERT && runB.result.status_code == EVMC_REVERT)
	{
		solAssert(
			runA.result.output_size == runB.result.output_size &&
			std::memcmp(runA.result.output_data, runB.result.output_data, runA.result.output_size) == 0,
			label + ": revert data differs"
		);
	}

	return 0;
}
