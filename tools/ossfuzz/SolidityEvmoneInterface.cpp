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

std::optional<CompilerOutput> SolidityCompilationFramework::compileContract()
{
	m_compiler.setSources(m_compilerInput.sourceCode);
	m_compiler.setLibraries(m_compilerInput.libraryAddresses);
	m_compiler.setEVMVersion(m_compilerInput.evmVersion);
	m_compiler.setOptimiserSettings(m_compilerInput.optimiserSettings);
	m_compiler.setViaIR(m_compilerInput.viaIR);
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
		std::string contractName;
		if (m_compilerInput.contractName.empty())
			contractName = m_compiler.lastContractName();
		else
			contractName = m_compilerInput.contractName;
		evmasm::LinkerObject obj = m_compiler.object(contractName);
		Json methodIdentifiers = m_compiler.interfaceSymbols(contractName)["methods"];
		return CompilerOutput{obj.bytecode, methodIdentifiers};
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
	auto cOutput = m_compilationFramework.compileContract();
	// Compilation can fail for generated inputs; return a failure result.
	if (!cOutput.has_value() ||
		cOutput->byteCode.empty() ||
		cOutput->methodIdentifiersInContract.empty())
		return evmc::Result{EVMC_INTERNAL_ERROR};

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
