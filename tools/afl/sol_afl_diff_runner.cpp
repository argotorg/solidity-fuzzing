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
#include <libsolutil/JSON.h>

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

/// Cap on the calldata region for the region-aware input format. Solidity
/// calldata in practice is rarely larger than a few KB; 64 KB is a defensive
/// upper bound that still lets AFL grow the buffer significantly via havoc.
static constexpr size_t s_maxCalldataBytes = 64 * 1024;

/// Indicates "skip this run" — caller compares two skips as equal so the
/// outer differential bails cleanly.
static RunResult skip()
{
	return RunResult{evmc::Result{EVMC_INTERNAL_ERROR}, false, {}, {}, {}, {}, {}};
}

/// Compile the source, deploy the resulting bytecode, send `_calldata` to
/// the deployment. Capture state for the differential check.
///
/// `_readsDeployedCode` is set to true if the contract performed
/// EXTCODESIZE/EXTCODECOPY/EXTCODEHASH on any address it deployed. The
/// caller uses this to skip the differential — those values depend on the
/// (config-dependent) deployed bytecode and are not real bugs.
static RunResult runOnce(
	langutil::EVMVersion _version,
	StringMap const& _source,
	OptimiserSettings _optimiserSettings,
	bool _viaIR,
	bytes const& _calldata,
	bool& _readsDeployedCode
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
	// ICEs are not interesting bugs, skipped here.
	catch (langutil::InternalCompilerError const&)     { return skip(); }
	catch (langutil::UnimplementedFeatureError const&) { return skip(); }
	catch (langutil::StackTooDeepError const&)         { return skip(); }
	catch (evmasm::StackTooDeepException const&)       { return skip(); }
	catch (yul::YulAssertion const&)                   { return skip(); }
	catch (yul::YulException const&)                   { return skip(); }
	// afl-ts ts-chaos can produce non-UTF-8 input bytes; solidity uses
	// nlohmann::json internally and throws on malformed UTF-8. Not a solc
	// bug — treat as a normal compile failure.
	catch (Json::exception const&)                     { return skip(); }

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

	_readsDeployedCode = host.m_readsDeployedCode;

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
		host.m_contractCreationOrder,
		// Carry the storage layout so the differential check below can mask
		// internal-function-pointer bytes (non-portable across optimiser modes).
		compOut->storageLayout
	};
}

/// Region-aware input format used together with the patched afl-ts:
///
///   [source bytes][calldata bytes][u16 LE source_len][0xCA 0xFE]
///
/// When the trailing magic 0xCA 0xFE is present, afl-ts mutates only the
/// source slice via tree-sitter splice while AFL's regular havoc /
/// bit-flipping freely mutates the calldata bytes. Inputs without magic
/// fall back to keccak-derived calldata so the existing pure-Solidity
/// corpus continues to work unchanged.
static std::pair<std::string, bytes> splitInput(std::string const& _input)
{
	if (_input.size() >= 4 &&
		static_cast<unsigned char>(_input[_input.size() - 2]) == 0xCA &&
		static_cast<unsigned char>(_input[_input.size() - 1]) == 0xFE)
	{
		size_t srcLen =
			static_cast<unsigned char>(_input[_input.size() - 4]) |
			(static_cast<size_t>(static_cast<unsigned char>(_input[_input.size() - 3])) << 8);
		if (srcLen <= _input.size() - 4)
		{
			std::string source = _input.substr(0, srcLen);
			bytes calldata(
				_input.begin() + static_cast<std::ptrdiff_t>(srcLen),
				_input.begin() + static_cast<std::ptrdiff_t>(_input.size() - 4)
			);
			return {std::move(source), std::move(calldata)};
		}
	}
	// No magic / invalid trailer: treat the whole input as source and
	// derive 32 calldata bytes from its hash. Same behavior as before
	// the region-aware format was introduced.
	return {_input, keccak256(_input).asBytes()};
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

	std::string input = readSource(argc, argv);
	if (input.empty() || input.size() > s_maxSourceBytes + s_maxCalldataBytes + 4)
		return 0;
	auto [source, calldata] = splitInput(input);
	if (source.empty() || source.size() > s_maxSourceBytes)
		return 0;
	if (calldata.size() > s_maxCalldataBytes)
		return 0;

	langutil::EVMVersion version = langutil::EVMVersion::current();
	StringMap sources({{"test.sol", source}});

	OptimiserSettings settingsA = OptimiserSettings::minimal();
	OptimiserSettings settingsB = OptimiserSettings::standard();

	// No outer try/catch on purpose. runOnce already swallows the known
	// non-bug exceptions; any InternalCompilerError reaching this scope —
	// including the one solAssert throws on a diff — must propagate so AFL
	// records a SIGABRT crash via terminate().
	bool const viaIR = false;
	bool readsDeployedCodeA = false;
	bool readsDeployedCodeB = false;
	auto runA = runOnce(version, sources, settingsA, viaIR, calldata, readsDeployedCodeA);
	auto runB = runOnce(version, sources, settingsB, viaIR, calldata, readsDeployedCodeB);

	// Skip on deployment failure (matches proto fuzzer behavior).
	// Also catches the bug-16642 invalid-opcode-codegen signature — covered, don't surface.
	if (runA.result.status_code != EVMC_SUCCESS && runA.result.status_code != EVMC_REVERT) return 0;
	if (runB.result.status_code != EVMC_SUCCESS && runB.result.status_code != EVMC_REVERT) return 0;

	// Skip on sub-call OOG — legitimate cross-optimisation difference.
	if (runA.subCallOutOfGas || runB.subCallOutOfGas) return 0;

	// Skip when the contract introspected its own (or any deployed contract's)
	// bytecode via EXTCODESIZE/EXTCODECOPY/EXTCODEHASH. The bytecode itself
	// differs across optimiser/codegen modes by design, so any output or
	// storage derived from those reads is a harness false positive.
	if (readsDeployedCodeA || readsDeployedCodeB) return 0;

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
		// Internal function pointers are encoded differently across legacy
		// (PCs) and IR (function IDs) and across optimiser levels (PCs shift
		// with bytecode size). Mask their storage bytes before the strict
		// equality check — see TODO.md for the full rationale.
		auto fpMasks = internalFunctionPointerMasks(runA.mainContractStorageLayout);
		if (!fpMasks.empty())
		{
			if (!runA.contractCreationOrder.empty())
				applyStorageMasks(runA.storage, runA.contractCreationOrder.front(), fpMasks);
			if (!runB.contractCreationOrder.empty())
				applyStorageMasks(runB.storage, runB.contractCreationOrder.front(), fpMasks);
		}
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
