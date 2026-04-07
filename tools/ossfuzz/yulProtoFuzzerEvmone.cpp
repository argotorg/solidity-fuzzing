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
 * Yul proto fuzzer with evmone-based differential testing.
 *
 * Generates Yul code from protobuf, compiles it twice, deploys both versions
 * on evmone, executes with the same calldata, and compares output, logs, and
 * storage — similar to sol_proto_ossfuzz_evmone but for Yul.
 *
 * Modes (controlled by compile definition):
 * - Default (yul_proto_ossfuzz_evmone): unoptimized vs optimized, both legacy codegen
 * - FUZZER_MODE_SSACFG (yul_proto_ossfuzz_evmone_ssacfg): unoptimized legacy vs
 *   optimized SSA CFG codegen
 * - FUZZER_MODE_CHECK_STACK_ALLOC (yul_proto_ossfuzz_evmone_check_stack_alloc):
 *   optimized without vs with stack allocation
 * - FUZZER_MODE_SINGLE_PASS (yul_proto_ossfuzz_evmone_single_pass): prerequisite
 *   passes only vs prerequisite + single optimizer pass. The target pass is
 *   selected at runtime via the FUZZER_PASS environment variable (a single
 *   character abbreviation, e.g. FUZZER_PASS=c for CommonSubexpressionEliminator).
 */

#include <tools/ossfuzz/yulProto.pb.h>
#include <tools/ossfuzz/protoToYul.h>
#include <tools/ossfuzz/FuzzerDiffCommon.h>

#include <tools/common/EVMHost.h>

#include <tools/ossfuzz/YulEvmoneInterface.h>

#include <libyul/Exceptions.h>

#include <libsolidity/interface/OptimiserSettings.h>

#include <libyul/optimiser/Suite.h>

#include <liblangutil/DebugInfoSelection.h>
#include <liblangutil/EVMVersion.h>

#include <evmone/evmone.h>

#include <src/libfuzzer/libfuzzer_macro.h>

#include <fstream>
#include <iostream>
#include <cstring>

using namespace solidity;
using namespace solidity::test;
using namespace solidity::test::fuzzer;
using namespace solidity::yul;
using namespace solidity::yul::test;
using namespace solidity::yul::test::yul_fuzzer;
using namespace solidity::langutil;
using namespace solidity::frontend;

static evmc::VM evmone = evmc::VM{evmc_create_evmone()};

/// Fuzzer mode selection (controlled by compile definitions):
/// - Default: unoptimized vs optimized (both legacy codegen)
/// - FUZZER_MODE_SSACFG: unoptimized (legacy) vs optimized (SSA CFG codegen)
/// - FUZZER_MODE_CHECK_STACK_ALLOC: optimized with optimizeStackAllocation off
///   vs optimized with optimizeStackAllocation on (both legacy codegen)
/// - FUZZER_MODE_SINGLE_PASS: prerequisite passes only vs prerequisite + single
///   optimizer pass (both legacy codegen). Pass selected via FUZZER_PASS env var.
#ifdef FUZZER_MODE_SSACFG
static constexpr bool s_modeSSACFG = true;
#else
static constexpr bool s_modeSSACFG = false;
#endif

#ifdef FUZZER_MODE_CHECK_STACK_ALLOC
static constexpr bool s_modeCheckStackAlloc = true;
#else
static constexpr bool s_modeCheckStackAlloc = false;
#endif

#ifdef FUZZER_MODE_SINGLE_PASS
static constexpr bool s_modeSinglePass = true;
#else
static constexpr bool s_modeSinglePass = false;
#endif

/// Gas limit for EVM execution — bounds runtime and memory usage
/// (prevents LOG/CALL spam from causing OOM or timeouts).
static constexpr int64_t s_gasLimit = 400000;

namespace
{

/// Deploy bytecode directly as creation code (for Yul objects that already
/// contain deployment logic — datacopy+return of runtime code).
static evmc::Result deployObjectCode(bytes const& _input, EVMHost& _host, int64_t _gas)
{
	evmc_message msg = {};
	msg.gas = _gas;
	msg.input_data = _input.data();
	msg.input_size = _input.size();
	msg.kind = EVMC_CREATE;
	return _host.call(msg);
}

/// Compile Yul source, deploy on evmone, execute with calldata, return results.
/// @param _isObject true if the input is a Yul object (deployment bytecode already
///   includes creation logic); false for plain blocks that need a deploy wrapper.
RunResult runYulOnce(
	EVMVersion _version,
	std::string const& _yulSource,
	OptimiserSettings _settings,
	bytes const& _calldata,
	bool _viaSSACFG = false,
	bool _isObject = false
)
{
	EVMHost hostContext(_version, evmone);
	hostContext.reset();

	bytes byteCode;
	try
	{
		YulAssembler assembler{_version, std::nullopt, _settings, _yulSource, _viaSSACFG};
		byteCode = assembler.assemble();
	}
	catch (solidity::yul::StackTooDeepError const&)
	{
		return RunResult{evmc::Result{EVMC_INTERNAL_ERROR}, false, {}, {}, {}, {}};
	}
	catch (solidity::yul::YulException const&)
	{
		// Parse/analysis/codegen failure — skip this input.
		return RunResult{evmc::Result{EVMC_INTERNAL_ERROR}, false, {}, {}, {}, {}};
	}
	catch (solidity::yul::YulAssertion const&)
	{
		// Parse/analysis assertion failure — skip this input.
		return RunResult{evmc::Result{EVMC_INTERNAL_ERROR}, false, {}, {}, {}, {}};
	}

	// Objects already contain deployment logic (datacopy+return of runtime code),
	// so deploy directly. Plain blocks need the deployCode wrapper.
	evmc::Result deployResult = _isObject
		? deployObjectCode(byteCode, hostContext, s_gasLimit)
		: YulEvmoneUtility::deployCode(byteCode, hostContext, s_gasLimit);
	if (deployResult.status_code != EVMC_SUCCESS)
		return RunResult{std::move(deployResult), false, {}, {}, {}, {}};

	auto callMsg = YulEvmoneUtility::callMessage(deployResult.create_address, _calldata);
	callMsg.gas = s_gasLimit;
	evmc::Result callResult = hostContext.call(callMsg);
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

	return RunResult{std::move(callResult), subCallOOG, std::move(logs), std::move(storage), std::move(transientStorage), std::move(contractCreationOrder)};
}

/// Returns the single-pass optimizer abbreviation from the FUZZER_PASS env var.
/// Validates it against the known pass abbreviations. Caches the result.
/// Aborts with a message if the env var is missing or invalid.
std::string getSinglePassAbbreviation()
{
	static std::string cached = []() -> std::string {
		char const* env = getenv("FUZZER_PASS");
		if (!env || strlen(env) != 1)
		{
			std::cerr << "FUZZER_MODE_SINGLE_PASS requires FUZZER_PASS env var set to a single "
				"optimizer step abbreviation character.\nValid abbreviations:\n";
			for (auto const& [abbr, name] : yul::OptimiserSuite::stepAbbreviationToNameMap())
				std::cerr << "  " << abbr << " = " << name << "\n";
			abort();
		}
		char abbr = env[0];
		auto const& map = yul::OptimiserSuite::stepAbbreviationToNameMap();
		if (map.find(abbr) == map.end())
		{
			std::cerr << "FUZZER_PASS='" << abbr << "' is not a valid optimizer step abbreviation.\n"
				"Valid abbreviations:\n";
			for (auto const& [a, name] : map)
				std::cerr << "  " << a << " = " << name << "\n";
			abort();
		}
		return std::string(1, abbr);
	}();
	return cached;
}

} // anonymous namespace

DEFINE_PROTO_FUZZER(Program const& _input)
{
	bool isObject = _input.has_obj();

	// filterStatefulInstructions=false: keep sstore/tstore/log — we compare them.
	// filterOptimizationNoise=true: filter datasize/dataoffset that inherently differ.
	bool filterStatefulInstructions = false;
	bool filterOptimizationNoise = true;
	ProtoConverter converter(
		filterStatefulInstructions,
		filterOptimizationNoise
	);
	std::string yul_source = converter.programToString(_input);
	// Always use the latest EVM version for maximum feature coverage.
	EVMVersion version = EVMVersion::current();
	auto calldata = converter.calldata();

	// Build optimizer sequences early so we can dump them
	std::string optimizerSeq = _input.optimiser_seq_size() > 0
		? buildOptimizerSequence(_input.optimiser_seq())
		: std::string(OptimiserSettings::DefaultYulOptimiserSteps);
	std::string optimizerCleanupSeq = _input.optimiser_cleanup_seq_size() > 0
		? buildOptimizerSequence(_input.optimiser_cleanup_seq())
		: std::string(OptimiserSettings::DefaultYulOptimiserCleanupSteps);

	if (const char* dump_path = getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		std::ofstream of(dump_path);
		of.write(yul_source.data(), static_cast<std::streamsize>(yul_source.size()));
	}
	if (const char* dump_path = getenv("PROTO_FUZZER_DUMP_SEQ_PATH"))
	{
		std::string content = "optimizer-sequence: " + optimizerSeq + "\n"
			+ "optimizer-cleanup-sequence: " + optimizerCleanupSeq + "\n";
		std::ofstream of(dump_path);
		of.write(content.data(), static_cast<std::streamsize>(content.size()));
	}

	YulStringRepository::reset();

	// --- Run A ---
	OptimiserSettings settingsA = OptimiserSettings::full();
	if (s_modeSinglePass)
	{
		// Single-pass mode: Run A uses the optimizer with an empty sequence.
		// OptimiserSuite::run() will still run the hard-coded prerequisite passes
		// (Disambiguator + hgfo) and post-processing (StackCompressor, NameSimplifier,
		// etc.), but no user-specified optimization steps.
		settingsA.runYulOptimiser = true;
		settingsA.optimizeStackAllocation = false;
		settingsA.yulOptimiserSteps = "";
		settingsA.yulOptimiserCleanupSteps = "";
	}
	else if (s_modeCheckStackAlloc)
	{
		// Check stack alloc mode: Run A is optimized but with stack allocation off.
		settingsA.runYulOptimiser = true;
		settingsA.optimizeStackAllocation = false;
	}
	else
	{
		// Default / SSACFG mode: Run A is unoptimized.
		settingsA.runYulOptimiser = false;
		settingsA.optimizeStackAllocation = false;
	}

	// Use custom optimizer sequence if provided in proto (for both modes that optimize)
	if (!s_modeSinglePass && settingsA.runYulOptimiser && _input.optimiser_seq_size() > 0)
	{
		settingsA.yulOptimiserSteps = optimizerSeq;
		settingsA.yulOptimiserCleanupSteps = optimizerCleanupSeq;
	}

	auto runA = runYulOnce(version, yul_source, settingsA, calldata, /*viaSSACFG=*/false, isObject);

	// Bail on deployment failure or serious call errors
	if (runA.result.status_code != EVMC_SUCCESS &&
		runA.result.status_code != EVMC_REVERT)
		return;

	// --- Run B ---
	OptimiserSettings settingsB = OptimiserSettings::full();
	if (s_modeSinglePass)
	{
		// Single-pass mode: Run B uses the optimizer with only the target pass.
		// Same prerequisites and post-processing as Run A, but with the single
		// target pass added. The only semantic difference is that one pass.
		std::string passAbbr = getSinglePassAbbreviation();
		settingsB.runYulOptimiser = true;
		settingsB.optimizeStackAllocation = false;
		settingsB.yulOptimiserSteps = passAbbr;
		settingsB.yulOptimiserCleanupSteps = "";
	}
	else
	{
		settingsB.runYulOptimiser = true;
		settingsB.optimizeStackAllocation = true;
	}

	// Use custom optimizer sequence if provided in proto
	if (!s_modeSinglePass && _input.optimiser_seq_size() > 0)
	{
		settingsB.yulOptimiserSteps = optimizerSeq;
		settingsB.yulOptimiserCleanupSteps = optimizerCleanupSeq;
	}

	// In SSACFG mode: run B uses the SSA CFG codegen backend.
	// In default / check-stack-alloc / single-pass mode: run B uses legacy codegen.
	auto runB = runYulOnce(version, yul_source, settingsB, calldata, /*viaSSACFG=*/s_modeSSACFG, isObject);

	// Skip comparison if either run hit gas-related or serious errors
	bool gasRelated =
		runA.result.status_code == EVMC_OUT_OF_GAS ||
		runB.result.status_code == EVMC_OUT_OF_GAS ||
		runA.subCallOutOfGas ||
		runB.subCallOutOfGas;
	if (gasRelated)
		return;

	if (YulEvmoneUtility::seriousCallError(runA.result.status_code) ||
		YulEvmoneUtility::seriousCallError(runB.result.status_code))
		return;

	std::string const modeLabel = s_modeSinglePass
		? "Yul evmone fuzzer (single pass '" + getSinglePassAbbreviation() + "'): "
		  "prerequisites only vs prerequisites + pass"
		: s_modeCheckStackAlloc
		? "Yul evmone fuzzer (check stack alloc): optimized without vs with stack allocation"
		: s_modeSSACFG
		? "Yul evmone fuzzer (SSACFG mode): unoptimized legacy vs optimized SSACFG"
		: "Yul evmone fuzzer: optimized vs non-optimized";

	// Compare status codes
	solAssert(
		runA.result.status_code == runB.result.status_code,
		modeLabel + " status code differs (A=" +
		std::to_string(runA.result.status_code) + " B=" +
		std::to_string(runB.result.status_code) + ")"
	);

	// Compare output, logs, and storage when both succeeded
	if (runA.result.status_code == EVMC_SUCCESS && runB.result.status_code == EVMC_SUCCESS)
	{
		solAssert(
			runA.result.output_size == runB.result.output_size &&
			std::memcmp(runA.result.output_data, runB.result.output_data, runA.result.output_size) == 0,
			modeLabel + " output differs"
		);
		solAssert(
			logsEqual(runA.logs, runB.logs),
			modeLabel + " logs differ"
		);
		solAssert(
			storageEqual(runA.storage, runA.contractCreationOrder, runB.storage, runB.contractCreationOrder),
			modeLabel + " storage differs"
		);
		solAssert(
			transientStorageEqual(runA.transientStorage, runA.contractCreationOrder, runB.transientStorage, runB.contractCreationOrder),
			modeLabel + " transient storage differs"
		);
	}

	// Compare revert data when both reverted
	if (runA.result.status_code == EVMC_REVERT && runB.result.status_code == EVMC_REVERT)
	{
		solAssert(
			runA.result.output_size == runB.result.output_size &&
			std::memcmp(runA.result.output_data, runB.result.output_data, runA.result.output_size) == 0,
			modeLabel + " revert data differs"
		);
	}
}
