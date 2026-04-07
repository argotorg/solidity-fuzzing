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
 * Standalone debug tool that reproduces the yul_proto_ossfuzz_evmone fuzzer's
 * compile-deploy-execute flow on a .yul file. Runs three configurations
 * (unoptimized, optimized legacy, optimized SSACFG) and dumps bytecodes, logs,
 * storage, and output for debugging differential testing failures.
 */

#include <tools/ossfuzz/YulEvmoneInterface.h>
#include <tools/common/EVMHost.h>

#include <libyul/Exceptions.h>
#include <libyul/optimiser/Suite.h>

#include <libsolidity/interface/OptimiserSettings.h>

#include <liblangutil/EVMVersion.h>

#include <boost/program_options.hpp>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <map>
#include <unordered_map>

namespace fs = std::filesystem;

using namespace solidity::test::fuzzer;
using namespace solidity::test;
using namespace solidity::frontend;
using namespace solidity::langutil;
using namespace solidity;

namespace po = boost::program_options;

// ANSI color codes
static constexpr char const* GREEN = "\033[32m";
static constexpr char const* RED = "\033[31m";
static constexpr char const* YELLOW = "\033[33m";
static constexpr char const* RESET = "\033[0m";

static constexpr int64_t s_gasLimit = 400000;

using TransientStorageMap = std::unordered_map<evmc::bytes32, evmc::bytes32>;

/// Result of a single compile-deploy-execute run.
struct RunResult
{
	bool compilationFailed = false;
	bool internalError = false;
	std::string internalErrorMsg;
	bytes bytecode;
	std::string optimizedIR;
	evmc_status_code statusCode = EVMC_INTERNAL_ERROR;
	bool subCallOutOfGas = false;
	bytes output;
	std::vector<evmc::MockedHost::log_record> logs;
	std::map<evmc::address, StorageMap> storage;
	std::map<evmc::address, TransientStorageMap> transientStorage;
	/// Contract creation order: addresses in the order they were deployed (CREATE/CREATE2).
	std::vector<evmc::address> contractCreationOrder;
};

static std::string statusCodeToString(evmc_status_code _code)
{
	switch (_code)
	{
	case EVMC_SUCCESS: return "SUCCESS";
	case EVMC_FAILURE: return "FAILURE";
	case EVMC_REVERT: return "REVERT";
	case EVMC_OUT_OF_GAS: return "OUT_OF_GAS";
	case EVMC_INVALID_INSTRUCTION: return "INVALID_INSTRUCTION";
	case EVMC_UNDEFINED_INSTRUCTION: return "UNDEFINED_INSTRUCTION";
	case EVMC_STACK_OVERFLOW: return "STACK_OVERFLOW";
	case EVMC_STACK_UNDERFLOW: return "STACK_UNDERFLOW";
	case EVMC_BAD_JUMP_DESTINATION: return "BAD_JUMP_DESTINATION";
	case EVMC_INVALID_MEMORY_ACCESS: return "INVALID_MEMORY_ACCESS";
	case EVMC_CALL_DEPTH_EXCEEDED: return "CALL_DEPTH_EXCEEDED";
	case EVMC_STATIC_MODE_VIOLATION: return "STATIC_MODE_VIOLATION";
	case EVMC_PRECOMPILE_FAILURE: return "PRECOMPILE_FAILURE";
	case EVMC_CONTRACT_VALIDATION_FAILURE: return "CONTRACT_VALIDATION_FAILURE";
	case EVMC_ARGUMENT_OUT_OF_RANGE: return "ARGUMENT_OUT_OF_RANGE";
	case EVMC_INTERNAL_ERROR: return "INTERNAL_ERROR";
	case EVMC_REJECTED: return "REJECTED";
	case EVMC_OUT_OF_MEMORY: return "OUT_OF_MEMORY";
	default: return "UNKNOWN(" + std::to_string(static_cast<int>(_code)) + ")";
	}
}

static std::string toHexString(bytes const& _data)
{
	std::ostringstream ss;
	for (uint8_t b : _data)
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
	return ss.str();
}

static std::string toHexString(evmc::bytes32 const& _data)
{
	std::ostringstream ss;
	for (uint8_t b : _data.bytes)
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
	return ss.str();
}

static std::string toHexString(evmc::address const& _addr)
{
	std::ostringstream ss;
	for (uint8_t b : _addr.bytes)
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
	return ss.str();
}

/// Expand an optimizer abbreviation sequence to human-readable step names.
/// E.g. "fDv" → "BlockFlattener, DeadCodeEliminator, SSAValueChecker"
/// Brackets and colons are preserved as-is.
static std::string expandOptimizerSequence(std::string const& _abbreviations)
{
	auto const& nameMap = yul::OptimiserSuite::stepAbbreviationToNameMap();
	std::string result;
	for (char c : _abbreviations)
	{
		if (c == '[' || c == ']' || c == ':' || c == ' ' || c == '\n')
		{
			if (!result.empty() && result.back() != ' ' && c != ']' && c != ':')
				result += ' ';
			result += c;
			if (c != ' ')
				result += ' ';
			continue;
		}
		auto it = nameMap.find(c);
		if (it != nameMap.end())
		{
			if (!result.empty() && result.back() != ' ' && result.back() != '[')
				result += ", ";
			result += it->second;
		}
	}
	return result;
}

/// Print optimizer sequence info: always prints the default sequence as reference,
/// then the used sequence (noting if it's the default).
static void printOptimizerSequences(
	std::string const& _usedSeq,
	std::string const& _usedCleanupSeq,
	std::ostream& _out
)
{
	std::string const defaultSeq = OptimiserSettings::DefaultYulOptimiserSteps;
	std::string const defaultCleanupSeq = OptimiserSettings::DefaultYulOptimiserCleanupSteps;

	bool seqIsDefault = (_usedSeq == defaultSeq);
	bool cleanupIsDefault = (_usedCleanupSeq == defaultCleanupSeq);

	_out << YELLOW << "========== OPTIMIZER SEQUENCES ==========" << RESET << std::endl;

	// Optimizer sequence
	_out << "  Default optimizer sequence:  " << defaultSeq << std::endl;
	_out << "    " << expandOptimizerSequence(defaultSeq) << std::endl;
	if (seqIsDefault)
		_out << GREEN << "  Used optimizer sequence:     (same as default)" << RESET << std::endl;
	else
	{
		_out << GREEN << "  Used optimizer sequence:     " << _usedSeq << RESET << std::endl;
		_out << GREEN << "    " << expandOptimizerSequence(_usedSeq) << RESET << std::endl;
	}

	_out << std::endl;

	// Cleanup sequence
	_out << "  Default cleanup sequence:   " << defaultCleanupSeq << std::endl;
	_out << "    " << expandOptimizerSequence(defaultCleanupSeq) << std::endl;
	if (cleanupIsDefault)
		_out << GREEN << "  Used cleanup sequence:      (same as default)" << RESET << std::endl;
	else
	{
		_out << GREEN << "  Used cleanup sequence:      " << _usedCleanupSeq << RESET << std::endl;
		_out << GREEN << "    " << expandOptimizerSequence(_usedCleanupSeq) << RESET << std::endl;
	}

	_out << std::endl;
}

static void writeToFile(std::string const& _path, std::string const& _content)
{
	std::ofstream f(_path);
	if (!f.is_open())
	{
		std::cerr << "Error: Cannot write to " << _path << std::endl;
		return;
	}
	f << _content;
	std::cout << "  Written: " << _path << std::endl;
}

/// Create an auto-named output directory "yul_debug_output-K" where K is the
/// smallest non-negative integer such that the directory doesn't already exist.
static std::string createOutputDir()
{
	for (int k = 0; ; ++k)
	{
		std::string dir = "yul_debug_output-" + std::to_string(k);
		if (!fs::exists(dir))
		{
			fs::create_directory(dir);
			return dir;
		}
	}
}

static RunResult runYulOnce(
	evmc::VM& _vm,
	EVMVersion _version,
	std::string const& _yulSource,
	OptimiserSettings _settings,
	bytes const& _calldata,
	bool _viaSSACFG = false,
	std::string const& _irOutputPath = {}
)
{
	RunResult result;
	EVMHost hostContext(_version, _vm);
	hostContext.reset();

	try
	{
		YulAssembler assembler{_version, std::nullopt, _settings, _yulSource, _viaSSACFG};
		assembler.parseAndOptimize();
		result.optimizedIR = assembler.printIR();
		// Write IR to disk immediately, before assembly which may OOM
		if (!_irOutputPath.empty())
		{
			std::ofstream irOut(_irOutputPath);
			if (irOut.is_open())
			{
				irOut << result.optimizedIR;
				std::cout << "  Yul IR (post-optimization, pre-codegen) written to: " << _irOutputPath << std::endl;
			}
			else
				std::cerr << "Error: Cannot write to " << _irOutputPath << std::endl;
		}
		result.bytecode = assembler.assembleOnly();
	}
	catch (solidity::yul::StackTooDeepError const&)
	{
		result.compilationFailed = true;
		result.internalErrorMsg = "StackTooDeepError";
		return result;
	}
	catch (solidity::yul::YulException const&)
	{
		result.compilationFailed = true;
		result.internalErrorMsg = "YulException (parse/analysis/codegen failure)";
		return result;
	}
	catch (solidity::yul::YulAssertion const&)
	{
		result.compilationFailed = true;
		result.internalErrorMsg = "YulAssertion (parse/analysis failure)";
		return result;
	}

	evmc::Result deployResult = YulEvmoneUtility::deployCode(result.bytecode, hostContext, s_gasLimit);
	if (deployResult.status_code != EVMC_SUCCESS)
	{
		result.statusCode = deployResult.status_code;
		return result;
	}

	auto callMsg = YulEvmoneUtility::callMessage(deployResult.create_address, _calldata);
	callMsg.gas = s_gasLimit;
	evmc::Result callResult = hostContext.call(callMsg);
	result.statusCode = callResult.status_code;
	result.subCallOutOfGas = hostContext.m_subCallOutOfGas;
	if (callResult.output_data && callResult.output_size > 0)
		result.output = bytes(callResult.output_data, callResult.output_data + callResult.output_size);

	// Capture logs
	result.logs.assign(hostContext.recorded_logs.begin(), hostContext.recorded_logs.end());

	// Capture storage
	for (auto const& [addr, account] : hostContext.accounts)
		if (!account.storage.empty())
			result.storage[addr] = account.storage;

	// Capture transient storage
	for (auto const& [addr, account] : hostContext.accounts)
		if (!account.transient_storage.empty())
			result.transientStorage[addr] = account.transient_storage;

	// Capture contract creation order
	result.contractCreationOrder = hostContext.m_contractCreationOrder;

	return result;
}

/// Compare logs ignoring creator address.
static bool logsEqual(
	std::vector<evmc::MockedHost::log_record> const& _a,
	std::vector<evmc::MockedHost::log_record> const& _b
)
{
	if (_a.size() != _b.size())
		return false;
	for (size_t i = 0; i < _a.size(); i++)
		if (_a[i].data != _b[i].data || _a[i].topics != _b[i].topics)
			return false;
	return true;
}

/// Filter out storage entries where current value is zero.
static std::map<evmc::address, StorageMap> filterZeroStorage(
	std::map<evmc::address, StorageMap> const& _storage
)
{
	static constexpr evmc::bytes32 zero{};
	std::map<evmc::address, StorageMap> filtered;
	for (auto const& [addr, storageMap] : _storage)
	{
		StorageMap nonZero;
		for (auto const& [key, val] : storageMap)
			if (val.current != zero)
				nonZero[key] = val;
		if (!nonZero.empty())
			filtered[addr] = std::move(nonZero);
	}
	return filtered;
}

/// Build a map from creation-order index to non-zero storage content.
/// Accounts not found in creationOrder are assigned indices after the last entry.
static std::map<size_t, StorageMap> normalizeStorageByCreationOrder(
	std::map<evmc::address, StorageMap> const& _storage,
	std::vector<evmc::address> const& _creationOrder
)
{
	auto filtered = filterZeroStorage(_storage);
	std::map<size_t, StorageMap> result;
	size_t unknownIdx = _creationOrder.size();
	for (auto const& [addr, storageMap] : filtered)
	{
		auto it = std::find(_creationOrder.begin(), _creationOrder.end(), addr);
		size_t idx = (it != _creationOrder.end())
			? static_cast<size_t>(std::distance(_creationOrder.begin(), it))
			: unknownIdx++;
		result[idx] = storageMap;
	}
	return result;
}

/// Compare storage maps for equality (comparing current values only).
/// Accounts are matched by CONTRACT CREATION ORDER (not by address), so that
/// different bytecodes producing different CREATE/CREATE2 addresses don't cause
/// false positives. Slots with value zero are filtered out (equivalent to unwritten).
static bool storageEqual(
	std::map<evmc::address, StorageMap> const& _a,
	std::vector<evmc::address> const& _creationOrderA,
	std::map<evmc::address, StorageMap> const& _b,
	std::vector<evmc::address> const& _creationOrderB
)
{
	auto normA = normalizeStorageByCreationOrder(_a, _creationOrderA);
	auto normB = normalizeStorageByCreationOrder(_b, _creationOrderB);
	if (normA.size() != normB.size())
		return false;
	for (auto const& [idx, storageA] : normA)
	{
		auto jt = normB.find(idx);
		if (jt == normB.end())
			return false;
		auto const& storageB = jt->second;
		if (storageA.size() != storageB.size())
			return false;
		for (auto const& [key, valA] : storageA)
		{
			auto kt = storageB.find(key);
			if (kt == storageB.end())
				return false;
			if (valA.current != kt->second.current)
				return false;
		}
	}
	return true;
}

/// Filter out transient storage entries where value is zero.
static std::map<evmc::address, TransientStorageMap> filterZeroTransientStorage(
	std::map<evmc::address, TransientStorageMap> const& _storage
)
{
	static constexpr evmc::bytes32 zero{};
	std::map<evmc::address, TransientStorageMap> filtered;
	for (auto const& [addr, storageMap] : _storage)
	{
		TransientStorageMap nonZero;
		for (auto const& [key, val] : storageMap)
			if (val != zero)
				nonZero[key] = val;
		if (!nonZero.empty())
			filtered[addr] = std::move(nonZero);
	}
	return filtered;
}

/// Compare transient storage maps positionally.
static bool transientStorageEqual(
	std::map<evmc::address, TransientStorageMap> const& _a,
	std::map<evmc::address, TransientStorageMap> const& _b
)
{
	auto filtA = filterZeroTransientStorage(_a);
	auto filtB = filterZeroTransientStorage(_b);
	if (filtA.size() != filtB.size())
		return false;
	auto itA = filtA.begin();
	auto itB = filtB.begin();
	for (; itA != filtA.end(); ++itA, ++itB)
	{
		auto const& storageA = itA->second;
		auto const& storageB = itB->second;
		if (storageA.size() != storageB.size())
			return false;
		for (auto const& [key, valA] : storageA)
		{
			auto jt = storageB.find(key);
			if (jt == storageB.end())
				return false;
			if (valA != jt->second)
				return false;
		}
	}
	return true;
}

static void printRunResult(std::string const& _label, RunResult const& _run, std::ostream& _out)
{
	_out << YELLOW << "=== " << _label << " ===" << RESET << std::endl;

	if (_run.compilationFailed)
	{
		_out << "  COMPILATION FAILED";
		if (!_run.internalErrorMsg.empty())
			_out << " (" << _run.internalErrorMsg << ")";
		_out << std::endl;
		return;
	}

	_out << "  Bytecode size: " << _run.bytecode.size() << " bytes" << std::endl;
	_out << "  Bytecode: " << toHexString(_run.bytecode) << std::endl;
	_out << "  Status: " << statusCodeToString(_run.statusCode) << std::endl;
	_out << "  Output (" << _run.output.size() << " bytes): " << toHexString(_run.output) << std::endl;

	_out << "  Logs (" << _run.logs.size() << "):" << std::endl;
	for (size_t i = 0; i < _run.logs.size(); i++)
	{
		auto const& log = _run.logs[i];
		_out << "    Log[" << i << "]:" << std::endl;
		_out << "      Creator: " << toHexString(log.creator) << std::endl;
		_out << "      Data (" << log.data.size() << " bytes): ";
		std::ostringstream dataSS;
		for (uint8_t b : log.data)
			dataSS << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
		_out << dataSS.str() << std::endl;
		_out << "      Topics (" << log.topics.size() << "):" << std::endl;
		for (size_t j = 0; j < log.topics.size(); j++)
			_out << "        [" << j << "]: " << toHexString(log.topics[j]) << std::endl;
	}

	auto filteredStorage = filterZeroStorage(_run.storage);
	_out << "  Storage (" << filteredStorage.size() << " accounts):" << std::endl;
	for (auto const& [addr, storageMap] : filteredStorage)
	{
		auto const& co = _run.contractCreationOrder;
		auto it = std::find(co.begin(), co.end(), addr);
		std::string creationTag = (it != co.end())
			? "[created #" + std::to_string(std::distance(co.begin(), it)) + "]"
			: "[unknown creation order]";
		_out << "    Account " << toHexString(addr) << " " << creationTag << " (" << storageMap.size() << " slots):" << std::endl;
		for (auto const& [key, val] : storageMap)
			_out << "      " << toHexString(key) << " => " << toHexString(val.current) << std::endl;
	}
	_out << std::endl;
}

/// @returns true if a mismatch was found.
static bool compareRuns(
	std::string const& _labelA,
	RunResult const& _a,
	std::string const& _labelB,
	RunResult const& _b,
	bool _quiet = false
)
{
	if (!_quiet)
		std::cout << "--- Comparing " << _labelA << " vs " << _labelB << " ---" << std::endl;

	if (_a.compilationFailed || _b.compilationFailed)
	{
		if (!_quiet)
			std::cout << "  SKIPPED (compilation failed: "
				<< _labelA << "=" << (_a.compilationFailed ? "yes" : "no") << ", "
				<< _labelB << "=" << (_b.compilationFailed ? "yes" : "no") << ")"
				<< std::endl;
		return false;
	}

	bool gasRelated =
		_a.statusCode == EVMC_OUT_OF_GAS || _b.statusCode == EVMC_OUT_OF_GAS ||
		_a.subCallOutOfGas || _b.subCallOutOfGas;

	static std::string const OOG_STR = std::string(YELLOW) + "OOG" + RESET;

	bool mismatch = false;
	auto matchStr = [](bool _match) -> std::string {
		return _match
			? std::string(GREEN) + "MATCH" + RESET
			: std::string(RED) + "DIFFER" + RESET;
	};

	// Status code
	bool statusMatch = (_a.statusCode == _b.statusCode);
	if (!gasRelated && !statusMatch) mismatch = true;
	if (!_quiet)
		std::cout << "  Status:  " << (gasRelated ? OOG_STR : matchStr(statusMatch))
			<< " (" << statusCodeToString(_a.statusCode) << " vs " << statusCodeToString(_b.statusCode) << ")"
			<< std::endl;

	if (_a.statusCode == EVMC_SUCCESS && _b.statusCode == EVMC_SUCCESS)
	{
		// Output
		bool outputMatch = (_a.output.size() == _b.output.size() &&
			std::memcmp(_a.output.data(), _b.output.data(), _a.output.size()) == 0);
		if (!gasRelated && !outputMatch) mismatch = true;

		// Logs
		bool logsMatch = logsEqual(_a.logs, _b.logs);
		if (!gasRelated && !logsMatch) mismatch = true;

		// Storage (compare by creation order to handle differing CREATE2 addresses)
		bool storageMatch = storageEqual(_a.storage, _a.contractCreationOrder, _b.storage, _b.contractCreationOrder);
		if (!gasRelated && !storageMatch) mismatch = true;

		// Transient storage
		bool transientMatch = transientStorageEqual(_a.transientStorage, _b.transientStorage);
		if (!gasRelated && !transientMatch) mismatch = true;

		if (!_quiet)
		{
			std::cout << "  Output:    " << (gasRelated ? OOG_STR : matchStr(outputMatch)) << std::endl;
			std::cout << "  Logs:      " << (gasRelated ? OOG_STR : matchStr(logsMatch)) << std::endl;
			std::cout << "  Storage:   " << (gasRelated ? OOG_STR : matchStr(storageMatch)) << std::endl;
			std::cout << "  Transient: " << (gasRelated ? OOG_STR : matchStr(transientMatch)) << std::endl;
		}
	}

	// Compare revert data when both reverted
	if (_a.statusCode == EVMC_REVERT && _b.statusCode == EVMC_REVERT)
	{
		bool revertMatch = (_a.output.size() == _b.output.size() &&
			std::memcmp(_a.output.data(), _b.output.data(), _a.output.size()) == 0);
		if (!gasRelated && !revertMatch) mismatch = true;
		if (!_quiet)
			std::cout << "  Revert data: " << (gasRelated ? OOG_STR : matchStr(revertMatch)) << std::endl;
	}

	if (!_quiet)
		std::cout << std::endl;
	return mismatch;
}

int main(int argc, char* argv[])
{
	po::options_description desc("yul_debug_runner - reproduce Yul fuzzer compile/deploy/execute");
	desc.add_options()
		("help,h", "Show help")
		("input-file", po::value<std::string>(), "Yul source file")
		("calldata", po::value<std::string>()->default_value(""), "Calldata in hex (e.g. \"a0ffba\"), passed to deployed contract")
		("optimizer-sequence", po::value<std::string>()->default_value(""), "Custom Yul optimizer step sequence (e.g. from fuzzer protobuf)")
		("optimizer-cleanup-sequence", po::value<std::string>()->default_value(""), "Custom Yul optimizer cleanup step sequence")
		("quiet,q", "Quiet mode: only print one-line summary, for use by delta debuggers")
		("verbose,v", "Verbose mode: print full logs and storage for all configs")
	;

	po::positional_options_description positional;
	positional.add("input-file", 1);

	po::variables_map vm;
	try
	{
		po::store(po::command_line_parser(argc, argv).options(desc).positional(positional).run(), vm);
		po::notify(vm);
	}
	catch (std::exception const& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
		return 2;
	}

	if (vm.count("help") || !vm.count("input-file"))
	{
		std::cout << "Usage: yul_debug_runner <file.yul> [--calldata <hex>] [--quiet]" << std::endl;
		std::cout << desc << std::endl;
		std::cout << std::endl;
		std::cout << "Exit codes:" << std::endl;
		std::cout << "  0 = all match (no bug)" << std::endl;
		std::cout << "  1 = mismatch found (differential bug)" << std::endl;
		std::cout << "  2 = normal compilation failure / file error" << std::endl;
		std::cout << "  3 = internal compiler error (assertion failure, crash)" << std::endl;
		return vm.count("help") ? 0 : 2;
	}

	std::string inputFile = vm["input-file"].as<std::string>();
	std::string calldataHex = vm["calldata"].as<std::string>();
	std::string optimizerSequence = vm["optimizer-sequence"].as<std::string>();
	std::string optimizerCleanupSequence = vm["optimizer-cleanup-sequence"].as<std::string>();
	bool quiet = vm.count("quiet") > 0;
	bool verbose = vm.count("verbose") > 0;

	// Read source file
	std::ifstream ifs(inputFile);
	if (!ifs.is_open())
	{
		std::cerr << "Error: Cannot open " << inputFile << std::endl;
		return 2;
	}
	std::string yulSource{std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>()};

	// Auto-create output directory and copy input file into it
	std::string outputDir;
	if (!quiet)
	{
		outputDir = createOutputDir();
		fs::copy_file(inputFile, outputDir + "/" + fs::path(inputFile).filename().string(),
			fs::copy_options::overwrite_existing);
		std::cout << "Output directory: " << outputDir << std::endl;
	}

	// Parse calldata
	bytes calldata;
	if (!calldataHex.empty())
	{
		calldata = util::fromHex(calldataHex);
		if (calldata.empty() && !calldataHex.empty())
		{
			std::cerr << "Error: Invalid hex calldata: " << calldataHex << std::endl;
			return 2;
		}
	}

	// Always use the latest EVM version (matching the fuzzer).
	EVMVersion version = EVMVersion::current();

	// Determine the actual optimizer sequences that will be used.
	std::string usedSeq = optimizerSequence.empty()
		? std::string(OptimiserSettings::DefaultYulOptimiserSteps)
		: optimizerSequence;
	std::string usedCleanupSeq = optimizerCleanupSequence.empty()
		? std::string(OptimiserSettings::DefaultYulOptimiserCleanupSteps)
		: optimizerCleanupSequence;

	if (!quiet)
	{
		std::cout << "Source file: " << inputFile << " (" << yulSource.size() << " bytes)" << std::endl;
		std::cout << "EVM version: " << version.name() << " (latest, hardcoded)" << std::endl;
		if (!calldataHex.empty())
			std::cout << "Calldata: " << calldataHex << std::endl;
		std::cout << std::endl;
		printOptimizerSequences(usedSeq, usedCleanupSeq, std::cout);
	}

	// Load evmone VM
	evmc::VM& evmVM = EVMHost::getVM("libevmone.so");
	if (!evmVM)
	{
		std::cerr << "Error: Could not load evmone VM. Set LD_LIBRARY_PATH to include evmone lib directory." << std::endl;
		return 2;
	}

	// Run 4 configurations: unoptimized, optimized (legacy), optimized (SSACFG),
	// optimized (legacy, no stack alloc)
	struct Config
	{
		std::string label;
		OptimiserSettings settings;
		bool viaSSACFG;
	};

	OptimiserSettings settingsNoOpt = OptimiserSettings::full();
	settingsNoOpt.runYulOptimiser = false;
	settingsNoOpt.optimizeStackAllocation = false;

	OptimiserSettings settingsOpt = OptimiserSettings::full();
	settingsOpt.runYulOptimiser = true;
	settingsOpt.optimizeStackAllocation = true;
	if (!optimizerSequence.empty())
		settingsOpt.yulOptimiserSteps = optimizerSequence;
	if (!optimizerCleanupSequence.empty())
		settingsOpt.yulOptimiserCleanupSteps = optimizerCleanupSequence;

	OptimiserSettings settingsOptNoStackAlloc = OptimiserSettings::full();
	settingsOptNoStackAlloc.runYulOptimiser = true;
	settingsOptNoStackAlloc.optimizeStackAllocation = false;
	if (!optimizerSequence.empty())
		settingsOptNoStackAlloc.yulOptimiserSteps = optimizerSequence;
	if (!optimizerCleanupSequence.empty())
		settingsOptNoStackAlloc.yulOptimiserCleanupSteps = optimizerCleanupSequence;

	std::vector<Config> configs = {
		{"unoptimized", settingsNoOpt, false},
		{"optimized_legacy", settingsOpt, false},
		{"optimized_ssacfg", settingsOpt, true},
		{"optimized_legacy_no_stack_alloc", settingsOptNoStackAlloc, false},
	};

	std::string irDir = outputDir.empty() ? "." : outputDir;

	// Derive solc binary path from argv[0]
	// argv[0] is like ".../build/tools/runners/yul_debug_runner", solc is at ".../build/solc/solc"
	std::string solcBinary;
	{
		std::string self = argv[0];
		auto pos = self.rfind('/');
		if (pos != std::string::npos)
			solcBinary = self.substr(0, pos) + "/../../solc/solc";
	}

	std::vector<RunResult> results;
	for (auto const& config : configs)
	{
		if (!quiet)
			std::cout << RED << "Running: " << config.label << "..." << RESET << std::endl;
		std::string irFile = quiet ? "" : irDir + "/" + config.label + ".yul";
		auto startTime = std::chrono::steady_clock::now();
		try
		{
			results.push_back(runYulOnce(evmVM, version, yulSource, config.settings, calldata, config.viaSSACFG, irFile));
		}
		catch (solidity::yul::StackTooDeepError const&)
		{
			if (!quiet)
				std::cout << "  StackTooDeepError" << std::endl;
			RunResult r;
			r.compilationFailed = true;
			r.internalErrorMsg = "StackTooDeepError";
			results.push_back(std::move(r));
		}
		catch (std::exception const& e)
		{
			if (!quiet)
				std::cout << "  Exception: " << e.what() << std::endl;
			RunResult r;
			r.compilationFailed = true;
			r.internalError = true;
			r.internalErrorMsg = e.what();
			results.push_back(std::move(r));
		}
		auto endTime = std::chrono::steady_clock::now();
		if (!quiet)
		{
			auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
			std::cout << "  Time: " << elapsedMs << " ms" << std::endl;

			// Build solc flags
			std::string solcFlags = " --strict-assembly";
			if (config.settings.runYulOptimiser)
			{
				solcFlags += " --optimize";
				if (!optimizerSequence.empty() || !optimizerCleanupSequence.empty())
				{
					std::string seq = optimizerSequence.empty()
						? std::string(OptimiserSettings::DefaultYulOptimiserSteps)
						: optimizerSequence;
					std::string cleanupSeq = optimizerCleanupSequence.empty()
						? std::string(OptimiserSettings::DefaultYulOptimiserCleanupSteps)
						: optimizerCleanupSequence;
					solcFlags += " --yul-optimizations \"" + seq + ":" + cleanupSeq + "\"";
				}
			}
			if (config.viaSSACFG)
				solcFlags += " --experimental --via-ssa-cfg";

			// Print equivalent solc command
			std::string irPath = irDir + "/" + config.label + ".yul";
			std::cout << "  Equivalent solc command: solc" << solcFlags << " " << irPath << std::endl;

			// Run perf profiling with solc on the original input file
			if (!solcBinary.empty())
			{
				std::string perfDataFile = irDir + "/" + config.label + ".perf.data";
				std::string perfReportFile = irDir + "/" + config.label + ".perf_top50.txt";
				std::string perfErrFile = irDir + "/" + config.label + ".perf.err";
				std::string perfRecordCmd = "/usr/bin/time --verbose perf record --call-graph fp -o " + perfDataFile
					+ " -- " + solcBinary + solcFlags + " " + inputFile + " > /dev/null 2>" + perfErrFile;
				int perfRet = std::system(perfRecordCmd.c_str());
				if (perfRet == 0)
				{
					// Parse max RSS from /usr/bin/time output
					std::ifstream timeStream(perfErrFile);
					if (timeStream.is_open())
					{
						std::string line;
						while (std::getline(timeStream, line))
						{
							if (line.find("Maximum resident set size") != std::string::npos)
							{
								auto colonPos = line.rfind(':');
								if (colonPos != std::string::npos)
								{
									std::string val = line.substr(colonPos + 1);
									val.erase(0, val.find_first_not_of(" \t"));
									val.erase(val.find_last_not_of(" \t") + 1);
									try {
										long kb = std::stol(val);
										std::cout << "  Peak memory: " << kb / 1024 << " MB (" << kb << " KB)" << std::endl;
									} catch (...) {}
								}
								break;
							}
						}
					}
					std::remove(perfErrFile.c_str());

					std::string perfReportCmd = "perf report -i " + perfDataFile
						+ " --stdio -g none"
						+ " 2>/dev/null | grep -v '^#' | sed 's/ \\[.\\] / /' | head -50 | cut -c1-200 > " + perfReportFile;
					std::system(perfReportCmd.c_str());
					std::cout << "  Perf top 50 written to: " << perfReportFile << std::endl;

					// Generate flame graph SVG via inferno
					std::string flameFile = irDir + "/" + config.label + ".flamegraph.svg";
					std::string flameCmd = "perf script -i " + perfDataFile
						+ " 2>/dev/null | inferno-collapse-perf 2>/dev/null | inferno-flamegraph > " + flameFile + " 2>/dev/null";
					int flameRet = std::system(flameCmd.c_str());
					if (flameRet == 0)
						std::cout << "  Flame graph written to: " << flameFile << std::endl;
					else
						std::cout << "  Flame graph: skipped (inferno not found?)" << std::endl;

					std::remove(perfDataFile.c_str());
				}
				else
				{
					std::cout << "  Perf failed. Command was:" << std::endl;
					std::cout << "    " << perfRecordCmd << std::endl;
					std::ifstream errStream(perfErrFile);
					if (errStream.is_open())
					{
						std::string errContents{std::istreambuf_iterator<char>(errStream), std::istreambuf_iterator<char>()};
						if (!errContents.empty())
							std::cout << "  Perf stderr: " << errContents;
					}
					std::remove(perfDataFile.c_str());
					std::remove(perfErrFile.c_str());
				}
			}
		}
	}

	if (!quiet && verbose)
	{
		std::cout << std::endl;

		// Print all results (verbose only — includes full bytecode, logs, storage)
		for (size_t i = 0; i < configs.size(); i++)
			printRunResult(configs[i].label, results[i], std::cout);
	}

	// Run differential comparisons
	bool anyMismatch = false;
	if (!quiet)
		std::cout << YELLOW << "========== DIFFERENTIAL COMPARISONS ==========" << RESET << std::endl << std::endl;

	// unoptimized vs optimized (legacy) — same as yul_proto_ossfuzz_evmone
	anyMismatch |= compareRuns(configs[0].label, results[0], configs[1].label, results[1], quiet);
	// unoptimized vs optimized (SSACFG) — same as yul_proto_ossfuzz_evmone_ssacfg
	anyMismatch |= compareRuns(configs[0].label, results[0], configs[2].label, results[2], quiet);
	// optimized legacy vs optimized SSACFG — cross-backend
	anyMismatch |= compareRuns(configs[1].label, results[1], configs[2].label, results[2], quiet);
	// optimized (no stack alloc) vs optimized (stack alloc) — same as _check_stack_alloc fuzzer
	anyMismatch |= compareRuns(configs[3].label, results[3], configs[1].label, results[1], quiet);

	if (!quiet)
	{
		// Print outputs
		std::cout << YELLOW << "========== OUTPUTS ==========" << RESET << std::endl << std::endl;
		for (size_t i = 0; i < configs.size(); i++)
		{
			std::cout << "--- " << configs[i].label << " ---" << std::endl;
			if (results[i].compilationFailed)
				std::cout << "  COMPILATION FAILED" << std::endl;
			else
			{
				std::cout << "  Status: " << statusCodeToString(results[i].statusCode) << std::endl;
				std::cout << "  Output (" << results[i].output.size() << " bytes): "
					<< toHexString(results[i].output) << std::endl;
			}
			std::cout << std::endl;
		}

		// Print log/storage summary (counts only unless --verbose)
		std::cout << YELLOW << "========== LOGS ==========" << RESET << std::endl;
		for (size_t i = 0; i < configs.size(); i++)
		{
			std::cout << "  " << configs[i].label << ": ";
			if (results[i].compilationFailed)
				std::cout << "COMPILATION FAILED";
			else
				std::cout << results[i].logs.size() << " logs";
			if (results[i].subCallOutOfGas)
				std::cout << " [sub-call OOG]";
			std::cout << std::endl;
		}
		std::cout << std::endl;

		if (verbose)
		{
			std::cout << "NOTE: Creator addresses differ across configs because different bytecodes" << std::endl;
			std::cout << "produce different CREATE/CREATE2 addresses. This is expected and not a bug." << std::endl;
			std::cout << std::endl;
			for (size_t i = 0; i < configs.size(); i++)
			{
				std::cout << "--- " << configs[i].label << " ---" << std::endl;
				if (results[i].compilationFailed)
					std::cout << "  COMPILATION FAILED" << std::endl;
				else if (results[i].logs.empty())
					std::cout << "  (no logs)" << std::endl;
				else
				{
					for (size_t j = 0; j < results[i].logs.size(); j++)
					{
						auto const& log = results[i].logs[j];
						std::cout << "  Log[" << j << "]:" << std::endl;
						std::cout << "    Creator: " << toHexString(log.creator) << std::endl;
						std::cout << "    Data (" << log.data.size() << " bytes): ";
						std::ostringstream dataSS;
						for (uint8_t b : log.data)
							dataSS << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(b);
						std::cout << dataSS.str() << std::endl;
						std::cout << "    Topics (" << log.topics.size() << "):" << std::endl;
						for (size_t k = 0; k < log.topics.size(); k++)
							std::cout << "      [" << k << "]: " << toHexString(log.topics[k]) << std::endl;
					}
				}
				std::cout << std::endl;
			}
		}

		// Print storage
		std::cout << YELLOW << "========== STORAGE ==========" << RESET << std::endl;
		for (size_t i = 0; i < configs.size(); i++)
		{
			auto filtered = filterZeroStorage(results[i].storage);
			std::cout << "  " << configs[i].label << ": ";
			if (results[i].compilationFailed)
				std::cout << "COMPILATION FAILED";
			else
				std::cout << filtered.size() << " accounts";
			std::cout << std::endl;
		}
		std::cout << std::endl;

		if (verbose)
		{
			std::cout << "NOTE: Account addresses differ across configs because different bytecodes" << std::endl;
			std::cout << "produce different CREATE/CREATE2 addresses. This is expected and not a bug." << std::endl;
			std::cout << "NOTE: Slots with value zero are hidden (equivalent to unwritten in the EVM)." << std::endl;
			std::cout << std::endl;
			for (size_t i = 0; i < configs.size(); i++)
			{
				std::cout << "--- " << configs[i].label << " ---" << std::endl;
				if (results[i].compilationFailed)
					std::cout << "  COMPILATION FAILED" << std::endl;
				else
				{
					auto filtered = filterZeroStorage(results[i].storage);
					if (filtered.empty())
						std::cout << "  (no storage)" << std::endl;
					else
					{
						for (auto const& [addr, storageMap] : filtered)
						{
							std::cout << "  Account " << toHexString(addr) << " (" << storageMap.size() << " slots):" << std::endl;
							for (auto const& [key, val] : storageMap)
								std::cout << "    " << toHexString(key) << " => " << toHexString(val.current) << std::endl;
						}
					}
				}
				std::cout << std::endl;
			}
		}

		// Write output files (outputDir is always set in non-quiet mode)
		std::cout << "Writing output files to: " << outputDir << std::endl;
		for (size_t i = 0; i < configs.size(); i++)
		{
			std::string prefix = outputDir + "/" + configs[i].label;
			if (!results[i].compilationFailed)
			{
				writeToFile(prefix + ".bytecode.hex", toHexString(results[i].bytecode));
				std::ostringstream logStream;
				printRunResult(configs[i].label, results[i], logStream);
				writeToFile(prefix + ".log", logStream.str());
			}
		}
	}

	// Check if any config hit an internal error or all failed to compile
	bool anyInternalError = false;
	bool allCompilationFailed = true;
	for (auto const& r : results)
	{
		if (r.internalError)
			anyInternalError = true;
		if (!r.compilationFailed)
			allCompilationFailed = false;
	}

	// Exit codes: 0 = all match, 1 = mismatch, 2 = compilation failure, 3 = internal error
	int exitCode;
	std::string summary;
	if (anyInternalError)
	{
		exitCode = 3;
		summary = "INTERNAL_ERROR";
	}
	else if (anyMismatch)
	{
		exitCode = 1;
		summary = "MISMATCH";
	}
	else if (allCompilationFailed)
	{
		exitCode = 2;
		summary = "COMPILATION_FAILED";
	}
	else
	{
		exitCode = 0;
		summary = "OK";
	}

	if (quiet)
		std::cout << summary << std::endl;

	return exitCode;
}
