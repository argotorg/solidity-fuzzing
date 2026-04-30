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

#pragma once

#include <tools/common/EVMHost.h>

#include <libsolidity/interface/CompilerStack.h>

#include <libyul/YulStack.h>

#include <libsolutil/Keccak256.h>

namespace solidity::test::fuzzer
{
struct CompilerOutput
{
	/// EVM bytecode returned by compiler
	solidity::bytes byteCode;
	/// Method identifiers in a contract
	Json methodIdentifiersInContract;
};

struct CompilerInput
{
	CompilerInput(
		langutil::EVMVersion _evmVersion,
		StringMap const& _sourceCode,
		std::string const& _contractName,
		frontend::OptimiserSettings _optimiserSettings,
		std::map<std::string, solidity::util::h160> _libraryAddresses,
		bool _debugFailure = false,
		bool _viaIR = false,
		bool _viaSSACFG = false
	):
		evmVersion(_evmVersion),
		sourceCode(_sourceCode),
		contractName(_contractName),
		optimiserSettings(_optimiserSettings),
		libraryAddresses(_libraryAddresses),
		debugFailure(_debugFailure),
		viaIR(_viaIR),
		viaSSACFG(_viaSSACFG)
	{}
	/// EVM target version
	langutil::EVMVersion evmVersion;
	/// Source code to be compiled
	StringMap const& sourceCode;
	/// Contract name without a colon prefix
	std::string contractName;
	/// Optimiser setting to be used during compilation
	frontend::OptimiserSettings optimiserSettings;
	/// Information on which library is deployed where
	std::map<std::string, solidity::util::h160> libraryAddresses;
	/// Flag used for debugging
	bool debugFailure;
	/// Flag to enable new code generator.
	bool viaIR;
	/// Flag to enable experimental SSA-CFG code generation (requires viaIR).
	bool viaSSACFG;
};

class SolidityCompilationFramework
{
public:
	SolidityCompilationFramework(CompilerInput _input): m_compilerInput(_input)
	{}
	/// Sets contract name to @param _contractName.
	void contractName(std::string const& _contractName)
	{
		m_compilerInput.contractName = _contractName;
	}
	/// Sets library addresses to @param _libraryAddresses.
	void libraryAddresses(std::map<std::string, solidity::util::h160> _libraryAddresses)
	{
		m_compilerInput.libraryAddresses = std::move(_libraryAddresses);
	}
	/// @returns method identifiers in contract called @param _contractName.
	Json methodIdentifiers(std::string const& _contractName)
	{
		return m_compiler.interfaceSymbols(_contractName)["methods"];
	}
	/// @returns the name of the last contract compiled (the convention solc
	/// uses when no explicit contract is requested).
	std::string lastContractName() const
	{
		return m_compiler.lastContractName();
	}
	/// @returns Compilation output comprising EVM bytecode and list of
	/// method identifiers in contract if compilation is successful,
	/// null value otherwise.
	std::optional<CompilerOutput> compileContract();
	/// @returns the optimized Yul IR for the given contract (only available when viaIR is enabled).
	std::optional<std::string> const& yulIROptimized(std::string const& _contractName) const
	{
		return m_compiler.yulIROptimized(_contractName);
	}
	/// @returns the unoptimized Yul IR for the given contract (only available when viaIR is enabled).
	std::optional<std::string> const& yulIR(std::string const& _contractName) const
	{
		return m_compiler.yulIR(_contractName);
	}
private:
	frontend::CompilerStack m_compiler;
	CompilerInput m_compilerInput;
};

class EvmoneUtility
{
public:
	EvmoneUtility(
		solidity::test::EVMHost& _evmHost,
		CompilerInput _compilerInput,
		std::string const& _contractName,
		std::string const& _libraryName,
		std::string const& _methodName,
		int64_t _gas = std::numeric_limits<int64_t>::max()
	):
		m_evmHost(_evmHost),
		m_compilationFramework(_compilerInput),
		m_contractName(_contractName),
		m_libraryName(_libraryName),
		m_methodName(_methodName),
		m_gas(_gas)
	{}
	/// @returns the result returned by the EVM host on compiling, deploying,
	/// and executing test configuration.
	/// @param _isabelleData contains encoding data to be passed to the
	/// isabelle test entry point.
	/// @param _extraCalldataHex hex-encoded bytes appended after the method
	/// selector when calling the test function (for fuzzing calldata).
	evmc::Result compileDeployAndExecute(
		std::string _isabelleData = {},
		std::string _extraCalldataHex = {}
	);
	/// Compares the contents of the memory address pointed to
	/// by `_result` of `_length` bytes to u256 zero.
	/// @returns true if `_result` is zero, false
	/// otherwise.
	static bool zeroWord(uint8_t const* _result, size_t _length);
	/// @returns an evmc_message with all of its fields zero
	/// initialized except gas and input fields.
	/// The gas field is set to @param _gas (default: maximum int64_t).
	/// The input field is copied from @param _input.
	static evmc_message initializeMessage(bytes const& _input, int64_t _gas = std::numeric_limits<int64_t>::max());
private:
	/// @returns the result of the execution of the function whose
	/// keccak256 hash is @param _functionHash that is deployed at
	/// @param _deployedAddress in @param _hostContext.
	evmc::Result executeContract(
		bytes const& _functionHash,
		evmc_address _deployedAddress
	);
	/// @returns the result of deployment of @param _code on @param _hostContext.
	evmc::Result deployContract(bytes const& _code);
	/// Deploys and executes EVM byte code in @param _byteCode on
	/// EVM Host referenced by @param _hostContext. Input passed
	/// to execution context is @param _hexEncodedInput.
	/// @returns result returning by @param _hostContext.
	evmc::Result deployAndExecute(
		bytes const& _byteCode,
		std::string const& _hexEncodedInput
	);
	/// Compiles contract named @param _contractName present in
	/// @param _sourceCode, optionally using a precompiled library
	/// specified via a library mapping and an optimisation setting.
	/// @returns a pair containing the generated byte code and method
	/// identifiers for methods in @param _contractName.
	std::optional<CompilerOutput> compileContract();

	/// EVM Host implementation
	solidity::test::EVMHost& m_evmHost;
	/// Solidity compilation framework
	SolidityCompilationFramework m_compilationFramework;
	/// Contract name
	std::string m_contractName;
	/// Library name
	std::string m_libraryName;
	/// Method name
	std::string m_methodName;
	/// Gas limit for EVM execution
	int64_t m_gas;
};

}
