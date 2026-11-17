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

#include <tools/ossfuzz/SolidityEvmoneInterface.h>

#include <liblangutil/Exceptions.h>
#include <liblangutil/SourceReferenceFormatter.h>

#include <range/v3/algorithm/all_of.hpp>
#include <range/v3/span.hpp>

using namespace solidity::test::fuzzer;
using namespace solidity::frontend;
using namespace solidity::langutil;
using namespace solidity::util;

namespace
{
std::string canonicalAbiType(solidity::Json const& _param)
{
	std::string const type = _param["type"];
	if (!type.starts_with("tuple"))
		return type;
	std::string members;
	for (solidity::Json const& component: _param["components"])
		members += (members.empty() ? "" : ",") + canonicalAbiType(component);
	return "(" + members + ")" + type.substr(5);
}
}

std::string SolidityCompilationFramework::defaultContractName() const
{
	std::vector<std::string> const sources = m_compiler.sourceNames();
	if (sources.empty())
		return {};
	ContractDefinition const* last = nullptr;
	for (auto const* contract: ASTNode::filteredNodes<ContractDefinition>(m_compiler.ast(sources.back()).nodes()))
		if (contract->contractKind() == ContractKind::Contract && !contract->abstract())
			last = contract;
	return last ? last->fullyQualifiedName() : m_compiler.lastContractName();
}

std::optional<CompilerOutput> SolidityCompilationFramework::compileContract()
{
	m_compiler.setSources(m_compilerInput.sourceCode);
	m_compiler.setLibraries(m_compilerInput.libraryAddresses);
	m_compiler.setEVMVersion(m_compilerInput.evmVersion);
	m_compiler.setOptimiserSettings(m_compilerInput.optimiserSettings);
	m_compiler.setViaIR(m_compilerInput.viaIR);
	if (m_compilerInput.viaSSACFG)
	{
		m_compiler.setExperimental(true);
		m_compiler.setViaSSACFG(true);
	}
	if (!m_compiler.compile())
	{
		if (m_compilerInput.debugFailure)
		{
			std::cerr << "Compiling contract failed" << std::endl;
			std::cerr << SourceReferenceFormatter::formatErrorInformation(
				m_compiler.errors(),
				m_compiler
			);
		}
		return {};
	}
	else
	{
		std::string const contractName =
			m_compilerInput.contractName.empty() ? defaultContractName() : m_compilerInput.contractName;
		m_deployedContractName = contractName;
		// A unit with no contract (only free functions, structs, interfaces...): nothing to deploy, and
		// CompilerStack::object("") would solAssert
		if (contractName.empty())
			return {};
		evmasm::LinkerObject obj = m_compiler.object(contractName);
		Json methodIdentifiers = m_compiler.interfaceSymbols(contractName)["methods"];
		Json storageLayout = m_compiler.storageLayout(contractName);

		std::map<util::h256, Json> layoutByRuntimeCode;
		for (std::string const& name: m_compiler.contractNames())
		{
			solidity::bytes const& runtimeCode = m_compiler.runtimeObject(name).bytecode;
			if (!runtimeCode.empty())
				layoutByRuntimeCode.emplace(util::keccak256(runtimeCode), m_compiler.storageLayout(name));
		}
		CompilerOutput output{obj.bytecode, methodIdentifiers, storageLayout, std::move(layoutByRuntimeCode)};
		output.linkReferences = obj.linkReferences;
		// Every library, not just the referenced ones: which libraries a bytecode references depends on the optimizer
		// (a dead reference may survive)
		if (!obj.linkReferences.empty())
			for (std::string const& name: m_compiler.contractNames())
				if (m_compiler.contractDefinition(name).isLibrary())
					output.libraries[name] = {m_compiler.object(name).bytecode, m_compiler.object(name).linkReferences};
		for (solidity::Json const& entry: m_compiler.contractABI(contractName))
			if (entry.value("type", "") == "constructor")
			{
				std::string params;
				for (solidity::Json const& input: entry["inputs"])
					params += (params.empty() ? "" : ",") + canonicalAbiType(input);
				if (!params.empty())
					output.constructorSignature = "constructor(" + params + ")";
				output.constructorPayable = entry.value("stateMutability", "") == "payable";
			}
			else if (entry.value("type", "") == "receive")
				output.hasReceive = true;
			else if (entry.value("type", "") == "fallback")
			{
				output.hasFallback = true;
				output.fallbackPayable = entry.value("stateMutability", "") == "payable";
			}
			else if (entry.value("type", "") == "function" && entry.value("stateMutability", "") == "payable")
			{
				std::string params;
				for (solidity::Json const& input: entry["inputs"])
					params += (params.empty() ? "" : ",") + canonicalAbiType(input);
				output.payableFunctions.insert(entry["name"].get<std::string>() + "(" + params + ")");
			}
		return output;
	}
}

bool EvmoneUtility::zeroWord(uint8_t const* _result, size_t _length)
{
	return _length == 32 &&
		ranges::all_of(
			ranges::span(_result, static_cast<long>(_length)),
			[](uint8_t _v) { return _v == 0; });
}

evmc_message EvmoneUtility::initializeMessage(bytes const& _input, int64_t _gas)
{
	// Zero initialize all message fields
	evmc_message msg = {};
	msg.gas = _gas;
	msg.input_data = _input.data();
	msg.input_size = _input.size();
	return msg;
}

evmc::Result EvmoneUtility::executeContract(
	bytes const& _functionHash,
	evmc_address _deployedAddress
)
{
	evmc_message message = initializeMessage(_functionHash, m_gas);
	message.recipient = _deployedAddress;
	message.code_address = _deployedAddress;
	message.kind = EVMC_CALL;
	return m_evmHost.call(message);
}

evmc::Result EvmoneUtility::deployContract(bytes const& _code)
{
	evmc_message message = initializeMessage(_code, m_gas);
	message.kind = EVMC_CREATE;
	return m_evmHost.call(message);
}

evmc::Result EvmoneUtility::deployAndExecute(
	bytes const& _byteCode,
	std::string const& _hexEncodedInput
)
{
	// Deploy contract — may fail for fuzzed inputs (e.g. constructor reverts)
	evmc::Result createResult = deployContract(_byteCode);
	if (createResult.status_code != EVMC_SUCCESS)
		return createResult;

	// Execute test function
	return executeContract(
		util::fromHex(_hexEncodedInput),
		createResult.create_address
	);
}

evmc::Result EvmoneUtility::compileDeployAndExecute(std::string _fuzzIsabelle, std::string _extraCalldataHex)
{
	std::map<std::string, h160> libraryAddressMap;
	// Stage 1: Compile and deploy library if present.
	if (!m_libraryName.empty())
	{
		m_compilationFramework.contractName(m_libraryName);
		auto compilationOutput = m_compilationFramework.compileContract();
		solAssert(compilationOutput.has_value(), "Compiling library failed");
		CompilerOutput cOutput = compilationOutput.value();
		// Deploy contract and signal failure if deploy failed
		evmc::Result createResult = deployContract(cOutput.byteCode);
		solAssert(
			createResult.status_code == EVMC_SUCCESS,
			"SolidityEvmoneInterface: Library deployment failed"
		);
		libraryAddressMap[m_libraryName] = EVMHost::convertFromEVMC(createResult.create_address);
		m_compilationFramework.libraryAddresses(libraryAddressMap);
	}

	// Stage 2: Compile, deploy, and execute contract, optionally using library
	// address map.
	m_compilationFramework.contractName(m_contractName);
	m_mainContractOutput.reset();
	auto cOutput = m_compilationFramework.compileContract();
	// Compilation can fail for generated inputs; return a failure result.
	if (!cOutput.has_value() ||
		cOutput->byteCode.empty() ||
		cOutput->methodIdentifiersInContract.empty())
		return evmc::Result{EVMC_INTERNAL_ERROR};
	// Cache for callers that need post-compile metadata (storage layout for
	// internal-function-pointer masking — see FuzzerDiffCommon).
	m_mainContractOutput = cOutput;

	std::string methodName;
	if (!_fuzzIsabelle.empty())
		// TODO: Remove this once a cleaner solution is found for querying
		// isabelle test entry point. At the moment, we are sure that the
		// entry point is the second method in the contract (hence the ++)
		// but not its name.
		methodName = (++cOutput->methodIdentifiersInContract.begin())->get<std::string>() +
			_fuzzIsabelle.substr(2, _fuzzIsabelle.size());
	else
		methodName = cOutput->methodIdentifiersInContract[m_methodName].get<std::string>();

	// Append extra calldata (hex-encoded) after the method selector
	methodName += _extraCalldataHex;

	return deployAndExecute(
		cOutput->byteCode,
		methodName
	);
}

std::optional<CompilerOutput> EvmoneUtility::compileContract()
{
	try
	{
		return m_compilationFramework.compileContract();
	}
	catch (evmasm::StackTooDeepException const&)
	{
		return {};
	}
}
