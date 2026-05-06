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
 * Standalone debug tool that reproduces the sol_proto_ossfuzz_evmone fuzzer's
 * compile-deploy-execute flow on a .sol file. Runs all 4 configurations
 * ({noOpt, opt} x {viaIR=true, viaIR=false}) and dumps bytecodes, logs,
 * storage, and output for debugging differential testing failures.
 *
 * Also accepts AFL-format inputs produced by sol_afl_diff_runner. Such files
 * carry a trailing magic — [src][calldata][u16 LE src_len][0xCA 0xFE] — that
 * splits the source from the raw calldata bytes. When the magic is detected,
 * we deploy the *last* contract in the source (matching AFL's behaviour) and
 * send the raw calldata directly, instead of looking up a `test()` selector
 * on a contract called `C`.
 */

#include <tools/ossfuzz/SolidityEvmoneInterface.h>
#include <tools/common/EVMHost.h>

#include <libevmasm/Exceptions.h>
#include <liblangutil/Exceptions.h>
#include <libsolutil/JSON.h>
#include <libsolutil/Keccak256.h>
#include <libyul/optimiser/Suite.h>

#include <boost/program_options.hpp>

#include <sys/wait.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <cstring>
#include <map>
#include <optional>
#include <unordered_map>

namespace fs = std::filesystem;

using namespace solidity::test::fuzzer;
using namespace solidity::test;
using namespace solidity::frontend;
using namespace solidity::langutil;
using namespace solidity::util;
using namespace solidity;

namespace po = boost::program_options;

// ANSI color codes
static constexpr char const* GREEN = "\033[32m";
static constexpr char const* RED = "\033[31m";
static constexpr char const* YELLOW = "\033[33m";
static constexpr char const* RESET = "\033[0m";

static constexpr int64_t s_gasLimit = 1000000;

using TransientStorageMap = std::unordered_map<evmc::bytes32, evmc::bytes32>;

/// Result of a single compile-deploy-execute run.
struct RunResult
{
	bool compilationFailed = false;
	bool internalError = false;  // Internal compiler error (assertion failure, etc.)
	std::string internalErrorMsg;
	bytes bytecode;
	std::string yulIR;
	std::string yulIROptimized;
	evmc_status_code statusCode = EVMC_INTERNAL_ERROR;
	bool subCallOutOfGas = false;
	bytes output;
	std::vector<evmc::MockedHost::log_record> logs;
	std::map<evmc::address, StorageMap> storage;
	std::map<evmc::address, TransientStorageMap> transientStorage;
	/// Contract creation order: addresses in the order they were deployed (CREATE/CREATE2).
	/// Index 0 is the main "C" contract, index 1+ are sub-contracts deployed during execution.
	std::vector<evmc::address> contractCreationOrder;
	/// Storage layout for the main contract — used to mask internal-function-
	/// pointer fields in the differential check (see TODO.md).
	Json mainContractStorageLayout;
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

static RunResult runOnce(
	evmc::VM& _vm,
	EVMVersion _version,
	StringMap const& _source,
	OptimiserSettings _optimiserSettings,
	bool _viaIR,
	bool _viaSSACFG = false,
	std::string const& _extraCalldataHex = {},
	std::optional<bytes> const& _aflRawCalldata = std::nullopt,
	bool _quiet = false
)
{
	RunResult result;
	EVMHost hostContext(_version, _vm);
	// Give the sender initial balance (matching fuzzer)
	hostContext.accounts[hostContext.tx_context.tx_origin].set_balance(0xffffffff);

	bool const aflMode = _aflRawCalldata.has_value();
	// In AFL mode the contract name is unknown — let solc use the *last*
	// contract in the source (matching sol_afl_diff_runner). Otherwise we
	// stick with "C" and look up a test() selector via EvmoneUtility.
	std::string const contractName = aflMode ? "" : "C";
	std::string const methodName = "test()";

	CompilerInput cInput(
		_version,
		_source,
		contractName,
		_optimiserSettings,
		{},
		/*debugFailure=*/!_quiet,
		_viaIR,
		_viaSSACFG
	);

	// First, compile separately to extract bytecode and IR for dumping.
	// In AFL mode we also reuse this bytecode to deploy directly below
	// (no second compile via EvmoneUtility).
	std::string actualContractName;
	{
		SolidityCompilationFramework compiler(cInput);
		auto compOutput = compiler.compileContract();
		if (compOutput.has_value() && !compOutput->byteCode.empty())
		{
			result.bytecode = compOutput->byteCode;
			result.mainContractStorageLayout = compOutput->storageLayout;
			actualContractName = contractName.empty()
				? compiler.lastContractName()
				: contractName;
			// Extract Yul IR (only available when viaIR is enabled)
			try
			{
				auto const& ir = compiler.yulIR("test.sol:" + actualContractName);
				if (ir.has_value())
					result.yulIR = *ir;
				auto const& irOpt = compiler.yulIROptimized("test.sol:" + actualContractName);
				if (irOpt.has_value())
					result.yulIROptimized = *irOpt;
			}
			catch (...) {}
		}
		else
		{
			result.compilationFailed = true;
			return result;
		}
	}

	evmc::Result evmResult{EVMC_INTERNAL_ERROR};
	if (aflMode)
	{
		// Manual deploy + raw-calldata call. Mirrors sol_afl_diff_runner so
		// the observable state matches what AFL saw when it found the crash.
		evmc_message createMsg = EvmoneUtility::initializeMessage(result.bytecode, s_gasLimit);
		createMsg.kind = EVMC_CREATE;
		evmc::Result createResult = hostContext.call(createMsg);
		if (createResult.status_code != EVMC_SUCCESS)
		{
			evmResult = std::move(createResult);
		}
		else
		{
			evmc_message callMsg = EvmoneUtility::initializeMessage(*_aflRawCalldata, s_gasLimit);
			callMsg.kind = EVMC_CALL;
			callMsg.recipient = createResult.create_address;
			callMsg.code_address = createResult.create_address;
			evmResult = hostContext.call(callMsg);
		}
	}
	else
	{
		EvmoneUtility evmoneUtil(
			hostContext,
			cInput,
			contractName,
			/*libraryName=*/"",
			methodName,
			s_gasLimit
		);
		evmResult = evmoneUtil.compileDeployAndExecute({}, _extraCalldataHex);
	}

	result.statusCode = evmResult.status_code;
	result.subCallOutOfGas = hostContext.m_subCallOutOfGas;
	if (evmResult.output_data && evmResult.output_size > 0)
		result.output = bytes(evmResult.output_data, evmResult.output_data + evmResult.output_size);

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

/// Compare logs ignoring creator address (which differs across optimization
/// levels because different bytecodes produce different CREATE/CREATE2 addresses).
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
/// In the EVM, an unwritten slot reads as zero, so a slot explicitly
/// set to zero is semantically identical to one that was never written.
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
/// Addresses that don't appear in creationOrder (e.g. precompiles, sender) are
/// assigned indices starting after the last creation-order entry.
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

/// Byte range within a single slot to ignore when comparing storage. Used
/// for internal-function-pointer fields whose encoding is not portable
/// across optimiser/codegen configs. Duplicated locally to keep this runner
/// self-contained — see equivalent helpers in tools/ossfuzz/FuzzerDiffCommon
/// (the runner avoids including that header to keep its own RunResult and
/// duplicated storageEqual independent).
struct StorageSlotMask
{
	u256 slot;
	unsigned offset;  ///< 0..31, byte offset within the slot
	unsigned length;  ///< number of bytes to mask
};

namespace
{
constexpr char const kInternalFunctionPrefix[] = "t_function_internal_";

void walkLayoutType(
	Json const& _types,
	std::string const& _typeKey,
	u256 const& _slot,
	unsigned _offset,
	std::vector<StorageSlotMask>& _out
)
{
	if (_typeKey.compare(0, sizeof(kInternalFunctionPrefix) - 1, kInternalFunctionPrefix) == 0)
	{
		unsigned length = 8;
		if (auto it = _types.find(_typeKey); it != _types.end())
			if (auto nb = it->find("numberOfBytes"); nb != it->end() && nb->is_string())
				length = static_cast<unsigned>(std::stoul(nb->get<std::string>()));
		_out.push_back({_slot, _offset, length});
		return;
	}
	auto typeIt = _types.find(_typeKey);
	if (typeIt == _types.end())
		return;
	Json const& typeInfo = *typeIt;
	auto encIt = typeInfo.find("encoding");
	if (encIt == typeInfo.end() || !encIt->is_string() || encIt->get<std::string>() != "inplace")
		return;  // mapping / dynamic_array / bytes — TODO: indirect-keyed storage
	if (auto membersIt = typeInfo.find("members"); membersIt != typeInfo.end() && membersIt->is_array())
	{
		for (auto const& member: *membersIt)
		{
			std::string mTypeKey = member.at("type").get<std::string>();
			u256 mSlotRel(member.at("slot").get<std::string>());
			unsigned mOffset = member.at("offset").get<unsigned>();
			walkLayoutType(_types, mTypeKey, _slot + mSlotRel, mOffset, _out);
		}
	}
	// Inplace static array (`base` key) intentionally not walked — see the
	// equivalent comment in FuzzerDiffCommon.cpp; no current finding needs it.
}
}

static std::vector<StorageSlotMask> internalFunctionPointerMasks(Json const& _layout)
{
	std::vector<StorageSlotMask> out;
	if (!_layout.is_object())
		return out;
	auto storageIt = _layout.find("storage");
	auto typesIt = _layout.find("types");
	if (storageIt == _layout.end() || !storageIt->is_array() ||
		typesIt == _layout.end() || !typesIt->is_object())
		return out;
	for (auto const& var: *storageIt)
	{
		std::string typeKey = var.at("type").get<std::string>();
		u256 slot(var.at("slot").get<std::string>());
		unsigned offset = var.at("offset").get<unsigned>();
		walkLayoutType(*typesIt, typeKey, slot, offset, out);
	}
	return out;
}

static void applyStorageMasks(
	std::map<evmc::address, StorageMap>& _storage,
	evmc::address const& _address,
	std::vector<StorageSlotMask> const& _masks
)
{
	if (_masks.empty())
		return;
	auto accIt = _storage.find(_address);
	if (accIt == _storage.end())
		return;
	StorageMap& slots = accIt->second;
	static constexpr evmc::bytes32 zero{};
	for (auto const& mask: _masks)
	{
		if (mask.length == 0 || mask.length > 32 || mask.offset >= 32 || mask.offset + mask.length > 32)
			continue;
		// First item in a slot is stored lower-order aligned; in big-endian
		// bytes32 layout the byte at offset O is at index 31-O.
		evmc::bytes32 key = EVMHost::convertToEVMC(h256(mask.slot));
		auto slotIt = slots.find(key);
		if (slotIt == slots.end())
			continue;
		evmc::bytes32& current = slotIt->second.current;
		unsigned const hi = 32 - mask.offset;
		unsigned const lo = hi - mask.length;
		for (unsigned i = lo; i < hi; ++i)
			current.bytes[i] = 0;
		if (current == zero)
			slots.erase(slotIt);
	}
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
		_out << "  COMPILATION FAILED" << std::endl;
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
		// Show creation index so accounts can be matched across runs with different bytecodes
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

		// Storage (compare by creation order to handle differing CREATE2 addresses).
		// Mask internal-function-pointer bytes first — their encoding is not
		// portable across optimiser/codegen modes (see TODO.md).
		auto storageA = _a.storage;
		auto storageB = _b.storage;
		auto fpMasks = internalFunctionPointerMasks(_a.mainContractStorageLayout);
		if (!fpMasks.empty())
		{
			if (!_a.contractCreationOrder.empty())
				applyStorageMasks(storageA, _a.contractCreationOrder.front(), fpMasks);
			if (!_b.contractCreationOrder.empty())
				applyStorageMasks(storageB, _b.contractCreationOrder.front(), fpMasks);
		}
		bool storageMatch = storageEqual(storageA, _a.contractCreationOrder, storageB, _b.contractCreationOrder);
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

/// Create an auto-named output directory "sol_debug_output-K" where K is the
/// smallest non-negative integer such that the directory doesn't already exist.
static std::string createOutputDir()
{
	for (int k = 0; ; ++k)
	{
		std::string dir = "sol_debug_output-" + std::to_string(k);
		if (!fs::exists(dir))
		{
			fs::create_directory(dir);
			return dir;
		}
	}
}

int main(int argc, char* argv[])
{
	po::options_description desc("sol_debug_runner - reproduce fuzzer compile/deploy/execute");
	desc.add_options()
		("help,h", "Show help")
		("input-file", po::value<std::string>(), "Solidity source file")
		("via-ir", po::value<bool>()->default_value(true), "Initial viaIR setting (default: true)")
		("calldata", po::value<std::string>()->default_value(""), "Extra calldata in hex (e.g. \"a0ffba\"), appended after method selector")
		("afl", "Treat input as AFL fuzzer file: deploy the last contract and send raw calldata (split via 0xCA 0xFE trailer, or keccak256(source) fallback)")
		("quiet,q", "Quiet mode: only print one-line summary, for use by delta debuggers")
		("verbose,v", "Verbose mode: print full logs and storage for all configs")
		("timeout", po::value<int>()->default_value(0),
			"Per-solc-invocation timeout in seconds (0 = disabled). When set, the "
			"in-process compile is replaced with an external `timeout N solc ...` "
			"subprocess, and the verbose-mode perf record solc is also wrapped with "
			"`timeout N`. Useful for hang triage; differential comparison is skipped.")
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
		std::cout << "Usage: sol_debug_runner <file.sol> [--via-ir true|false] [--calldata <hex>] [--afl] [--quiet]" << std::endl;
		std::cout << "Pass --afl to reproduce sol_afl_diff_runner inputs: the last contract" << std::endl;
		std::cout << "is deployed and the raw calldata (from 0xCA 0xFE trailer or keccak256" << std::endl;
		std::cout << "fallback) is sent without any test() selector lookup." << std::endl;
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
	bool viaIR = vm["via-ir"].as<bool>();
	std::string extraCalldataHex = vm["calldata"].as<std::string>();
	bool aflInput = vm.count("afl") > 0;
	bool quiet = vm.count("quiet") > 0;
	bool verbose = vm.count("verbose") > 0;
	int timeoutSecs = vm["timeout"].as<int>();
	if (timeoutSecs < 0)
	{
		std::cerr << "Error: --timeout must be >= 0" << std::endl;
		return 2;
	}

	// Read source file. Open in binary mode because AFL inputs may contain
	// non-text bytes in the calldata region trailing the magic suffix.
	std::ifstream ifs(inputFile, std::ios::binary);
	if (!ifs.is_open())
	{
		std::cerr << "Error: Cannot open " << inputFile << std::endl;
		return 2;
	}
	std::string solSource{std::istreambuf_iterator<char>(ifs), std::istreambuf_iterator<char>()};

	// AFL mode: mirror sol_afl_diff_runner's splitInput().
	//   [src bytes][calldata bytes][u16 LE src_len][0xCA 0xFE]  (region-aware)
	// or, when no magic trailer is present, fall back to keccak256(source) as
	// the 32-byte calldata. Either way the source we feed to solc may be a
	// strict prefix of the file; the calldata is sent raw to the deployed
	// (last) contract. Without --afl we treat the file as a plain .sol source.
	std::optional<bytes> aflRawCalldata;
	bool aflMagicSeen = false;
	if (aflInput)
	{
		if (solSource.size() >= 4 &&
			static_cast<unsigned char>(solSource[solSource.size() - 2]) == 0xCA &&
			static_cast<unsigned char>(solSource[solSource.size() - 1]) == 0xFE)
		{
			size_t srcLen =
				static_cast<unsigned char>(solSource[solSource.size() - 4]) |
				(static_cast<size_t>(static_cast<unsigned char>(solSource[solSource.size() - 3])) << 8);
			if (srcLen <= solSource.size() - 4)
			{
				bytes calldata(
					solSource.begin() + static_cast<std::ptrdiff_t>(srcLen),
					solSource.begin() + static_cast<std::ptrdiff_t>(solSource.size() - 4)
				);
				solSource.resize(srcLen);
				aflRawCalldata = std::move(calldata);
				aflMagicSeen = true;
			}
		}
		if (!aflMagicSeen)
			aflRawCalldata = keccak256(solSource).asBytes();
	}

	// Auto-create output directory and copy input file into it
	std::string outputDir;
	std::string sourcePath;  // path to clean source.sol inside outputDir (for --afl reuse)
	if (!quiet)
	{
		outputDir = createOutputDir();
		fs::copy_file(inputFile, outputDir + "/" + fs::path(inputFile).filename().string(),
			fs::copy_options::overwrite_existing);
		// Always write the (possibly AFL-trimmed) Solidity source as a standalone
		// file so the user can feed it directly to solc for bytecode reproduction.
		sourcePath = outputDir + "/source.sol";
		{
			std::ofstream srcFile(sourcePath);
			srcFile << solSource;
		}
		std::cout << "Output directory: " << outputDir << std::endl;
		std::cout << "  Wrote clean source: " << sourcePath << std::endl;
		if (aflRawCalldata.has_value())
		{
			std::string calldataPath = outputDir + "/calldata.hex";
			std::ofstream cdFile(calldataPath);
			cdFile << toHexString(*aflRawCalldata) << std::endl;
			std::cout << "  Wrote raw calldata: " << calldataPath << std::endl;
		}
	}

	if (!quiet)
	{
		std::cout << "Source file: " << inputFile;
		if (aflInput)
			std::cout << " [AFL " << (aflMagicSeen ? "magic-trailer" : "keccak-fallback")
				<< "] (source=" << solSource.size()
				<< " bytes, calldata=" << aflRawCalldata->size() << " bytes)";
		else
			std::cout << " (" << solSource.size() << " bytes)";
		std::cout << std::endl;
		std::cout << "viaIR: " << (viaIR ? "true" : "false") << std::endl;
		std::cout << "Gas limit: " << s_gasLimit << std::endl;
		if (aflRawCalldata.has_value())
		{
			std::cout << "AFL raw calldata: " << toHexString(*aflRawCalldata) << std::endl;
			if (!extraCalldataHex.empty())
				std::cout << "(ignoring --calldata in AFL mode; raw calldata from input is used)" << std::endl;
		}
		else if (!extraCalldataHex.empty())
			std::cout << "Extra calldata: " << extraCalldataHex << std::endl;
		std::cout << std::endl;
		// Sol debug runner always uses default optimizer sequences
		printOptimizerSequences(
			OptimiserSettings::DefaultYulOptimiserSteps,
			OptimiserSettings::DefaultYulOptimiserCleanupSteps,
			std::cout
		);
	}

	// Load evmone VM (relies on LD_LIBRARY_PATH to find the shared library)
	evmc::VM& evmVM = EVMHost::getVM("libevmone.so");
	if (!evmVM)
	{
		std::cerr << "Error: Could not load evmone VM. Set LD_LIBRARY_PATH to include evmone lib directory." << std::endl;
		return 2;
	}

	EVMVersion version = EVMVersion::current();
	StringMap source({{"test.sol", solSource}});

	// Run 5 configurations: 4 baseline {noOpt,opt} × {viaIR,!viaIR} plus one
	// experimental SSA-CFG run (which forces viaIR=true per solc requirement).
	struct Config
	{
		std::string label;
		OptimiserSettings optimiser;
		bool viaIR;
		bool optimize;
		bool viaSSACFG;
	};

	std::vector<Config> configs = {
		{"noOpt_viaIR=" + std::string(viaIR ? "true" : "false"), OptimiserSettings::minimal(), viaIR, false, false},
		{"opt_viaIR=" + std::string(viaIR ? "true" : "false"), OptimiserSettings::standard(), viaIR, true, false},
		{"noOpt_viaIR=" + std::string(!viaIR ? "true" : "false"), OptimiserSettings::minimal(), !viaIR, false, false},
		{"opt_viaIR=" + std::string(!viaIR ? "true" : "false"), OptimiserSettings::standard(), !viaIR, true, false},
		{"opt_ssaCFG", OptimiserSettings::standard(), /*viaIR=*/true, /*optimize=*/true, /*viaSSACFG=*/true},
	};

	// Build the equivalent solc command line for a config.
	// solc's CLI without --optimize uses OptimiserSettings::minimal() and with
	// --optimize uses ::standard() (see solc/CommandLineParser.cpp), so the
	// mapping is exact for default optimizer sequences.
	std::string const evmVersionName = version.name();
	auto solcInvocation = [&](Config const& _cfg, std::string const& _srcArg) {
		std::ostringstream s;
		s << "solc --bin --evm-version " << evmVersionName;
		if (_cfg.optimize)
			s << " --optimize";
		if (_cfg.viaIR)
			s << " --via-ir";
		if (_cfg.viaSSACFG)
			s << " --experimental --via-ssa-cfg";
		s << " " << _srcArg;
		return s.str();
	};

	std::string irDir = outputDir.empty() ? "." : outputDir;
	std::string const srcArg = sourcePath.empty() ? "<source.sol>" : sourcePath;

	// Derive solc binary path from argv[0] (mirrors yul_debug_runner).
	// argv[0] is like ".../build/tools/runners/sol_debug_runner"; solc lives at
	// ".../build/solidity/solc/solc".
	std::string solcBinary;
	{
		std::string self = argv[0];
		auto pos = self.rfind('/');
		if (pos != std::string::npos)
			solcBinary = self.substr(0, pos) + "/../../solidity/solc/solc";
	}

	std::vector<RunResult> results;
	for (auto const& config : configs)
	{
		if (!quiet)
		{
			std::cout << "Running: " << config.label << "..." << std::endl;
			std::cout << "  solc equivalent: " << solcInvocation(config, srcArg) << std::endl;
		}
		auto startTime = std::chrono::steady_clock::now();
		if (timeoutSecs > 0)
		{
			// Hang-triage mode: skip the in-process compile (which has no way
			// to be interrupted) and run an external `timeout N solc ...`
			// subprocess instead. We don't get bytecode / EVM execution out of
			// this, so the differential block further down is skipped.
			std::string solcFlags = " --bin --evm-version " + evmVersionName;
			if (config.optimize)
				solcFlags += " --optimize";
			if (config.viaIR)
				solcFlags += " --via-ir";
			if (config.viaSSACFG)
				solcFlags += " --experimental --via-ssa-cfg";
			std::string srcPathArg = sourcePath.empty() ? inputFile : sourcePath;
			std::string cmd = "timeout " + std::to_string(timeoutSecs) + " "
				+ solcBinary + solcFlags + " " + srcPathArg + " > /dev/null 2>&1";
			int rc = std::system(cmd.c_str());
			RunResult r;
			r.compilationFailed = true;
			if (WIFEXITED(rc) && WEXITSTATUS(rc) == 124)
			{
				r.internalError = true;
				r.internalErrorMsg = "timed out >" + std::to_string(timeoutSecs) + "s";
				if (!quiet)
					std::cout << "  TIMED OUT (>" << timeoutSecs << "s)" << std::endl;
			}
			results.push_back(std::move(r));
		}
		else
		{
			try
			{
				results.push_back(runOnce(evmVM, version, source, config.optimiser, config.viaIR, config.viaSSACFG, extraCalldataHex, aflRawCalldata, quiet));
			}
			catch (evmasm::StackTooDeepException const&)
			{
				if (!quiet)
					std::cout << "  StackTooDeep exception" << std::endl;
				RunResult r;
				r.compilationFailed = true;
				results.push_back(std::move(r));
			}
			catch (langutil::InternalCompilerError const& e)
			{
				if (!quiet)
					std::cout << "  InternalCompilerError: " << e.what() << std::endl;
				RunResult r;
				r.compilationFailed = true;
				r.internalError = true;
				r.internalErrorMsg = e.what();
				results.push_back(std::move(r));
			}
			catch (langutil::UnimplementedFeatureError const& e)
			{
				if (!quiet)
					std::cout << "  UnimplementedFeatureError: " << e.what() << std::endl;
				RunResult r;
				r.compilationFailed = true;
				r.internalError = true;
				r.internalErrorMsg = e.what();
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
		}
		auto endTime = std::chrono::steady_clock::now();

		// Write Yul IR files immediately so they're available even if a later config hangs/OOMs
		if (!quiet)
		{
			auto elapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
			std::cout << "  Time: " << elapsedMs << " ms" << std::endl;

			auto const& result = results.back();
			std::string irFile = irDir + "/" + config.label + ".yul";
			std::string irOptFile = irDir + "/" + config.label + ".optimized.yul";
			if (result.compilationFailed)
				std::cout << "  IR: COMPILATION FAILED (no IR)" << std::endl;
			else if (result.yulIR.empty() && result.yulIROptimized.empty())
				std::cout << "  IR: (no IR available, viaIR not enabled)" << std::endl;
			else
			{
				if (!result.yulIR.empty())
				{
					writeToFile(irFile, result.yulIR);
					std::cout << "    ^ Yul IR (pre-optimization) for " << config.label << std::endl;
				}
				if (!result.yulIROptimized.empty())
				{
					writeToFile(irOptFile, result.yulIROptimized);
					std::cout << "    ^ Yul IR (post-optimization, pre-codegen) for " << config.label << std::endl;
				}
			}

			// Run perf record + flame graph on the equivalent solc invocation,
			// using the clean source.sol path (works in both AFL and non-AFL mode).
			// Mirrors yul_debug_runner.cpp.
			if (!solcBinary.empty() && !sourcePath.empty())
			{
				std::string solcFlags = " --bin --evm-version " + evmVersionName;
				if (config.optimize)
					solcFlags += " --optimize";
				if (config.viaIR)
					solcFlags += " --via-ir";
				if (config.viaSSACFG)
					solcFlags += " --experimental --via-ssa-cfg";

				std::string perfDataFile = irDir + "/" + config.label + ".perf.data";
				std::string perfReportFile = irDir + "/" + config.label + ".perf_top50.txt";
				std::string perfErrFile = irDir + "/" + config.label + ".perf.err";
				std::string timeoutPrefix = timeoutSecs > 0
					? ("timeout " + std::to_string(timeoutSecs) + " ")
					: std::string();
				std::string perfRecordCmd = "/usr/bin/time --verbose perf record --call-graph fp -o " + perfDataFile
					+ " -- " + timeoutPrefix + solcBinary + solcFlags + " " + sourcePath + " > /dev/null 2>" + perfErrFile;
				int perfRet = std::system(perfRecordCmd.c_str());
				// Accept inner-solc timeout (exit 124) as success: perf.data is
				// still valid up to the timeout, so the top-50 report is useful.
				bool perfOk = perfRet == 0
					|| (timeoutSecs > 0 && WIFEXITED(perfRet) && WEXITSTATUS(perfRet) == 124);
				if (perfOk)
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

	// Run differential comparisons (same as fuzzer)
	bool anyMismatch = false;
	if (!quiet)
		std::cout << YELLOW << "========== DIFFERENTIAL COMPARISONS ==========" << RESET << std::endl << std::endl;

	// Same viaIR: noOpt vs opt
	anyMismatch |= compareRuns(configs[0].label, results[0], configs[1].label, results[1], quiet);
	// Opposite viaIR: noOpt vs opt
	anyMismatch |= compareRuns(configs[2].label, results[2], configs[3].label, results[3], quiet);
	// Cross viaIR: noOpt(viaIR) vs noOpt(!viaIR)
	anyMismatch |= compareRuns(configs[0].label, results[0], configs[2].label, results[2], quiet);
	// Cross viaIR: opt(viaIR) vs opt(!viaIR)
	anyMismatch |= compareRuns(configs[1].label, results[1], configs[3].label, results[3], quiet);

	if (!quiet)
	{
		// Print outputs for all configs
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

	// Check if any config hit an internal compiler error or all failed to compile
	bool anyInternalError = false;
	bool allCompilationFailed = true;
	for (auto const& r : results)
	{
		if (r.internalError)
			anyInternalError = true;
		if (!r.compilationFailed)
			allCompilationFailed = false;
	}

	// Exit codes: 0 = all match, 1 = mismatch, 2 = normal compilation failure, 3 = internal compiler error
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
