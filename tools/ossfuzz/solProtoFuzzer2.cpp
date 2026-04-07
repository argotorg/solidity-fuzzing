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

#include <tools/ossfuzz/protoToSol2.h>
#include <tools/ossfuzz/SolidityEvmoneInterface.h>
#include <tools/ossfuzz/FuzzerDiffCommon.h>
#include <tools/ossfuzz/sol2Proto.pb.h>

#include <tools/common/EVMHost.h>

#include <libevmasm/Exceptions.h>
#include <liblangutil/Exceptions.h>

#include <libyul/YulString.h>

#include <evmone/evmone.h>
#include <src/libfuzzer/libfuzzer_macro.h>

#include <fstream>
#include <cstring>

static evmc::VM evmone = evmc::VM{evmc_create_evmone()};

using namespace solidity::test::fuzzer;
using namespace solidity::test::sol2protofuzzer;
using namespace solidity;
using namespace solidity::frontend;
using namespace solidity::test;
using namespace solidity::util;

/// Gas limit for EVM execution — low enough to keep fuzzing fast,
/// high enough to deploy and run simple contracts.
static constexpr int64_t s_gasLimit = 1000000;

/// Fuzzer mode selection (controlled by compile definitions):
/// - Default: unoptimized vs optimized (same viaIR flag)
/// - FUZZER_MODE_VIAIR: unoptimized (legacy) vs optimized (viaIR)
#ifdef FUZZER_MODE_VIAIR
static constexpr bool s_modeViaIR = true;
#else
static constexpr bool s_modeViaIR = false;
#endif

/// Helper: compile, deploy, and execute a test contract.
/// Returns RunResult with evmc::Result, logs, and storage.
static RunResult runOnce(
	langutil::EVMVersion _version,
	StringMap const& _source,
	OptimiserSettings _optimiserSettings,
	bool _viaIR,
	std::string const& _extraCalldataHex = {}
)
{
	EVMHost hostContext(_version, evmone);
	// Give the sender (tx.origin) some initial balance so that value
	// transfers in .call{value:...}() work during testing.
	hostContext.accounts[hostContext.tx_context.tx_origin].set_balance(0xffffffff);
	std::string contractName = "C";
	std::string methodName = "test()";
	CompilerInput cInput(
		_version,
		_source,
		contractName,
		_optimiserSettings,
		{},
		/*debugFailure=*/false,
		_viaIR
	);
	EvmoneUtility evmoneUtil(
		hostContext,
		cInput,
		contractName,
		/*libraryName=*/"",
		methodName,
		s_gasLimit
	);
	evmc::Result result = evmoneUtil.compileDeployAndExecute({}, _extraCalldataHex);
	bool subCallOOG = hostContext.m_subCallOutOfGas;

	// Capture logs
	std::vector<evmc::MockedHost::log_record> logs(
		hostContext.recorded_logs.begin(),
		hostContext.recorded_logs.end()
	);

	// Capture storage for all accounts
	std::map<evmc::address, StorageMap> storage;
	for (auto const& [addr, account] : hostContext.accounts)
		if (!account.storage.empty())
			storage[addr] = account.storage;

	// Capture transient storage for all accounts
	std::map<evmc::address, TransientStorageMap> transientStorage;
	for (auto const& [addr, account] : hostContext.accounts)
		if (!account.transient_storage.empty())
			transientStorage[addr] = account.transient_storage;

	std::vector<evmc::address> contractCreationOrder = hostContext.m_contractCreationOrder;

	return RunResult{std::move(result), subCallOOG, std::move(logs), std::move(storage), std::move(transientStorage), std::move(contractCreationOrder)};
}

DEFINE_PROTO_FUZZER(Program const& _input)
{
	yul::YulStringRepository::reset();

	ProtoConverter converter;
	std::string sol_source = converter.protoToSolidity(_input);

	if (char const* dump_path = getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		std::ofstream of(dump_path);
		of.write(sol_source.data(), static_cast<std::streamsize>(sol_source.size()));
	}

	if (char const* dump_path = getenv("SOL_DEBUG_FILE"))
	{
		sol_source.clear();
		std::ifstream ifstr(dump_path);
		sol_source = {
			std::istreambuf_iterator<char>(ifstr),
			std::istreambuf_iterator<char>()
		};
		std::cout << sol_source << std::endl;
	}

	// Skip overly large sources — they compile slowly and reduce throughput
	if (sol_source.size() > 3000)
		return;

	// Always fuzz the latest EVM version to maximize feature coverage
	// (transient storage, EOF, etc.). Do NOT parameterize this.
	langutil::EVMVersion version = langutil::EVMVersion::current();
	bool viaIR = _input.via_ir();
	StringMap source({{"test.sol", sol_source}});

	// Convert proto calldata bytes to hex for appending after the method selector
	std::string extraCalldataHex;
	if (_input.has_calldata_data())
	{
		bytes calldataBytes(_input.calldata_data().begin(), _input.calldata_data().end());
		extraCalldataHex = toHex(calldataBytes);
	}

	try
	{
		// Build custom optimizer sequences from proto if provided
		std::string optimizerSeq = _input.optimiser_seq_size() > 0
			? buildOptimizerSequence(_input.optimiser_seq())
			: std::string(OptimiserSettings::DefaultYulOptimiserSteps);
		std::string optimizerCleanupSeq = _input.optimiser_cleanup_seq_size() > 0
			? buildOptimizerSequence(_input.optimiser_cleanup_seq())
			: std::string(OptimiserSettings::DefaultYulOptimiserCleanupSteps);

		// Choose settings for the two runs based on mode
		OptimiserSettings settingsA, settingsB;
		bool viaIR_A, viaIR_B;
		std::string modeLabel;
		if (s_modeViaIR)
		{
			settingsA = OptimiserSettings::minimal();
			settingsB = OptimiserSettings::standard();
			settingsB.yulOptimiserSteps = optimizerSeq;
			settingsB.yulOptimiserCleanupSteps = optimizerCleanupSeq;
			viaIR_A = false;
			viaIR_B = true;
			modeLabel = "Sol proto2 fuzzer (viaIR mode)";
		}
		else
		{
			settingsA = OptimiserSettings::minimal();
			settingsB = OptimiserSettings::standard();
			settingsB.yulOptimiserSteps = optimizerSeq;
			settingsB.yulOptimiserCleanupSteps = optimizerCleanupSeq;
			viaIR_A = viaIR;
			viaIR_B = viaIR;
			modeLabel = "Sol proto2 fuzzer";
		}

		// Always run both configurations
		auto runA = runOnce(version, source, settingsA, viaIR_A, extraCalldataHex);
		auto runB = runOnce(version, source, settingsB, viaIR_B, extraCalldataHex);

		// Skip on deployment failure (neither run produced a callable contract)
		if (runA.result.status_code != EVMC_SUCCESS &&
			runA.result.status_code != EVMC_REVERT)
			return;
		if (runB.result.status_code != EVMC_SUCCESS &&
			runB.result.status_code != EVMC_REVERT)
			return;

		// Skip on sub-call gas differences (legitimate across optimization levels).
		// Note: EVMC_OUT_OF_GAS as a top-level status is already filtered above
		// (not SUCCESS and not REVERT), so only subCallOutOfGas is checked here.
		if (runA.subCallOutOfGas || runB.subCallOutOfGas)
			return;

		// Compare status codes (catches success-vs-revert mismatches)
		solAssert(
			runA.result.status_code == runB.result.status_code,
			modeLabel + ": status code differs (A=" +
			std::to_string(runA.result.status_code) + " B=" +
			std::to_string(runB.result.status_code) + ")"
		);

		// Compare output/logs/storage when both succeeded
		if (runA.result.status_code == EVMC_SUCCESS && runB.result.status_code == EVMC_SUCCESS)
		{
			solAssert(
				runA.result.output_size == runB.result.output_size &&
				std::memcmp(runA.result.output_data, runB.result.output_data, runA.result.output_size) == 0,
				modeLabel + ": output differs"
			);
			solAssert(
				logsEqual(runA.logs, runB.logs),
				modeLabel + ": logs differ"
			);
			solAssert(
				storageEqual(runA.storage, runA.contractCreationOrder, runB.storage, runB.contractCreationOrder),
				modeLabel + ": storage differs"
			);
			solAssert(
				transientStorageEqual(runA.transientStorage, runA.contractCreationOrder, runB.transientStorage, runB.contractCreationOrder),
				modeLabel + ": transient storage differs"
			);
		}

		// Compare revert data when both reverted
		if (runA.result.status_code == EVMC_REVERT && runB.result.status_code == EVMC_REVERT)
		{
			solAssert(
				runA.result.output_size == runB.result.output_size &&
				std::memcmp(runA.result.output_data, runB.result.output_data, runA.result.output_size) == 0,
				modeLabel + ": revert data differs"
			);
		}
	}
	catch (evmasm::StackTooDeepException const&)
	{
		// Stack-too-deep in legacy codegen is expected for some inputs.
	}
	catch (langutil::StackTooDeepError const&)
	{
		// Stack-too-deep in IR codegen is expected for some inputs.
	}
}
