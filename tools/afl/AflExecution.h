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
/// What sol_afl_diff_runner executes for one input, shared with `sol_debug_runner --afl` so a crash
/// replays exactly: deploy the last contract, run the source's isoltest call script (`// ----` section),
/// then call every public function with ABI-encoded arguments drawn from the input's calldata region.

#pragma once

#include <tools/ossfuzz/FuzzerDiffCommon.h>
#include <tools/common/EVMHost.h>

#include <libsolutil/CommonData.h>
#include <libsolutil/FixedHash.h>
#include <libsolutil/JSON.h>
#include <libsolutil/Numeric.h>

#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace solidity::frontend
{
class CompilerStack;
}

namespace solidity::test::fuzzer
{
struct CompilerOutput;
}

namespace solidity::test::fuzzer::afl
{

struct AflInput
{
	std::string source;
	/// Raw calldata region of the region-aware format, else bytes derived from keccak256(source)
	bytes entropy;
	/// The calldata region verbatim, sent as an extra raw call (it is what AFL havoc mutates)
	std::optional<bytes> rawCalldata;
};

/// [source][calldata][u16 LE source_len][0xCA 0xFE], or a plain source
AflInput splitInput(std::string_view _input);

/// Splits isoltest `==== Source: name ====` sections; nullopt for inputs we cannot compile as given
/// (external sources).
std::optional<StringMap> sourceUnits(std::string const& _source);
/// sourceUnits() without dropping `pragma solidity` version constraints
std::optional<StringMap> sourceUnitsVerbatim(std::string const& _source);

struct PlannedCall
{
	std::string signature;
	bytes calldata;
	u256 value;
};

struct CallPlan
{
	bytes constructorArgs;
	u256 constructorValue;
	std::vector<PlannedCall> calls;
};

/// Depends only on the source, the (config-independent) ABI and the entropy, so every config runs the same plan.
/// What the call plan needs from the compiled contract; the same in every config
struct ContractInterface
{
	Json methodIdentifiers;
	/// Canonical, e.g. "constructor(uint256,(address,bool))"; empty if it takes no arguments
	std::string constructorSignature;
	bool constructorPayable = false;
	std::set<std::string> payableFunctions;
	bool hasReceive = false;
	bool hasFallback = false;
	bool fallbackPayable = false;
};

/// Without an isoltest constructor() line, constructor arguments are generated too.
CallPlan planCalls(AflInput const& _input, ContractInterface const& _interface);
ContractInterface interfaceOf(CompilerOutput const& _output);

struct CallObservation
{
	evmc_status_code status;
	bytes output;
	bool subCallOutOfGas;
	std::map<evmc::address, TransientStorageMap> transientStorage;
	std::vector<EVMHost::SubCall> subCalls;
	/// After a successful call: a later call can overwrite what this one wrote wrongly
	std::optional<std::map<evmc::address, StorageMap>> storage;
};

struct Execution
{
	evmc_status_code deployStatus = EVMC_FAILURE;
	std::vector<EVMHost::SubCall> deploySubCalls;
	std::map<evmc::address, evmc::bytes32> balances;
	std::vector<CallObservation> calls;
	/// Final state, with the fields FuzzerDiffCommon compares
	RunResult state;
	bool readsDeployedCode = false;
};

/// Deployment gets the block gas limit: unoptimized real-world contracts cost millions in code deposit alone
constexpr int64_t deployGas = 30'000'000;
constexpr int64_t callGas = 10'000'000;

Execution execute(EVMHost& _host, bytes const& _bytecode, CallPlan const& _plan);

struct Comparison
{
	/// Why the runs were not (fully) compared: config-dependent observations such as gas or deployed bytecode
	std::optional<std::string> skipped;
	std::vector<std::string> differences;
	/// Storage was not compared: an internal function pointer could not be masked
	bool storageUnmaskable = false;
};

/// The differential oracle. `storageLayouts` must be set on both states.
Comparison compare(Execution const& _a, Execution const& _b);

/// Why the compiled sources may legitimately behave differently across configs, or nullopt:
/// with @param _legacyVsIR the documented semantic changes (docs/ir-breaking-changes.rst); with
/// @param _legacyOptimizer internal function pointer comparison, which solc itself warns about.
/// Metamorphic variant of the compiled sources: some value-typed expressions inside function bodies, picked by
/// @param _seed, become calls of an identity function. Same semantics, different inlining/optimizer decisions.
/// nullopt if nothing was rewritten.
/// After a failed compile: the sources with each undeclared identifier replaced by a name that is in scope there
/// (state variables, functions, parameters, earlier locals; type names for unresolved paths), chosen by a hash.
/// Mutations splice in foreign identifiers, and this is their most common compile error. nullopt if nothing to do.
std::optional<StringMap> repairUndeclaredIdentifiers(frontend::CompilerStack const& _compiler, StringMap const& _sources);

std::optional<StringMap> wrapInIdentityCalls(frontend::CompilerStack const& _compiler, util::h256 const& _seed);

std::optional<std::string> configDependentSemantics(
	frontend::CompilerStack const& _compiler, bool _legacyVsIR, bool _legacyOptimizer);

}
