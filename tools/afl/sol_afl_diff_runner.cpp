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
/// AFL++ persistent-mode harness over tree-sitter-mutated Solidity. Compiles the source under the two
/// configs of the build's mode (see s_configs), runs the same call plan on both (AflExecution.h) and
/// solAsserts that deploy, every call's status/output/transient storage, logs and storage agree. The
/// ICE mode only compiles, under four configs, and lets ICEs escape. A filename argument replays one input.

#include <tools/afl/AflExecution.h>
#include <tools/ossfuzz/SolidityEvmoneInterface.h>
#include <tools/ossfuzz/FuzzerDiffCommon.h>
#include <tools/common/EVMHost.h>

#include <libevmasm/Exceptions.h>
#include <liblangutil/Exceptions.h>
#include <libyul/Exceptions.h>
#include <libyul/YulString.h>
#include <libyul/optimiser/Suite.h>
#include <libsolutil/Keccak256.h>
#include <libsolutil/CommonData.h>
#include <libsolutil/CommonIO.h>
#include <libsolutil/JSON.h>

#include <boost/exception/diagnostic_information.hpp>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <string_view>
#include <unistd.h>

// AFL++ persistent-mode + shared-memory fuzzing macros. With afl-clang-fast
// these expand to hooks into the AFL shared-memory ring; with any other
// compiler (e.g. a host repro build) the shim stubs them out so the binary
// still compiles and runs one input from stdin per process — matching the
// pre-persistent-mode behaviour.
#ifndef __AFL_FUZZ_TESTCASE_LEN
static ssize_t fuzz_len;
static unsigned char fuzz_buf[1024 * 1024];
  #define __AFL_FUZZ_TESTCASE_LEN fuzz_len
  #define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
  #define __AFL_FUZZ_INIT()
  #define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0 ? 1 : 0)
  #define __AFL_INIT() do {} while (0)
#endif

__AFL_FUZZ_INIT();

using namespace solidity;
using namespace solidity::frontend;
using namespace solidity::test;
using namespace solidity::test::fuzzer;
using namespace solidity::util;

/// Lazily resolved on first use via dlopen — same approach as sol_debug_runner.
/// Path is RPATH-baked into the executable (see CMakeLists.txt), so neither
/// LD_LIBRARY_PATH nor an absolute path is needed at runtime.
static evmc::VM& evmone() { return EVMHost::getVM("libevmone.so"); }

/// afl-ts splices keep growing inputs; real-world corpus entries routinely exceed the proto fuzzer's 3 KB
static constexpr size_t s_maxSourceBytes = 16 * 1024;
static constexpr size_t s_maxCalldataBytes = 64 * 1024;

struct Config
{
	char const* name;
	bool viaIR;
	bool optimize;
	bool viaSSACFG = false;
	/// Yul optimizer step sequence and `runs` drawn from the input
	bool randomOptimizer = false;
	/// Paris instead of the current EVM version: no PUSH0, MCOPY or transient storage, so different lowering
	bool oldEVM = false;
};

#if defined(AFL_MODE_ICE)
static constexpr Config s_configs[] = {
	{"legacy", false, false}, {"legacy-opt", false, true}, {"ir", true, false}, {"ir-opt", true, true}};
#elif defined(AFL_MODE_VIAIR)
static constexpr Config s_configs[] = {{"legacy-opt", false, true}, {"ir-opt", true, true}};
#elif defined(AFL_MODE_VIAIR_OPT)
static constexpr Config s_configs[] = {{"ir", true, false}, {"ir-opt", true, true}};
#elif defined(AFL_MODE_SSACFG)
static constexpr Config s_configs[] = {{"ir-opt", true, true}, {"ssacfg-opt", true, true, true}};
#elif defined(AFL_MODE_OPTSEQ)
static constexpr Config s_configs[] = {{"ir-opt", true, true}, {"ir-opt-random-steps", true, true, false, true}};
#elif defined(AFL_MODE_METAMORPHIC)
static constexpr Config s_configs[] = {{"ir-opt", true, true}, {"ir-opt-identity-wrapped", true, true}};
#elif defined(AFL_MODE_EVMVERSION)
static constexpr Config s_configs[] = {{"ir-opt", true, true}, {"ir-opt-paris", true, true, false, false, true}};
#else
static constexpr Config s_configs[] = {{"legacy", false, false}, {"legacy-opt", false, true}};
#endif

static bool verbose() { static bool const v = std::getenv("AFL_RUNNER_VERBOSE"); return v; }

/// Where an input stopped, for afl_sweep.py
static void stop(std::string const& _why)
{
	if (verbose())
		std::cerr << "stop: " << _why << "\n";
}

static constexpr bool s_legacyVsIR = s_configs[0].viaIR != s_configs[1].viaIR;
static constexpr bool s_legacyOptimizer = (!s_configs[0].viaIR && s_configs[0].optimize) ||
	(!s_configs[1].viaIR && s_configs[1].optimize);

static langutil::EVMVersion evmVersion(Config const& _config)
{
	return _config.oldEVM ? langutil::EVMVersion::paris() : langutil::EVMVersion::current();
}

/// Steps drawn from @param _seed (a hash of the input), so a source mutation also re-rolls the sequence
static OptimiserSettings optimiserSettings(Config const& _config, util::h256 const& _seed)
{
	OptimiserSettings settings = _config.optimize ? OptimiserSettings::standard() : OptimiserSettings::minimal();
	if (!_config.randomOptimizer)
		return settings;
	static std::string const steps = [] {
		std::string all;
		for (auto const& [abbreviation, _]: yul::OptimiserSuite::stepAbbreviationToNameMap())
			all += abbreviation;
		return all;
	}();
	util::h256 entropy = _seed;
	std::string sequence;
	std::size_t const length = 4 + entropy[0] % 28;
	for (std::size_t i = 0; i < length; ++i)
	{
		if (i % 31 == 30)
			entropy = util::keccak256(entropy.asBytes());
		sequence += steps[entropy[1 + i % 31] % steps.size()];
	}
	settings.yulOptimiserSteps = sequence;
	static constexpr std::size_t runs[] = {1, 200, 1000000};
	settings.expectedExecutionsPerDeployment = runs[entropy[31] % 3];
	if (verbose())
		std::cerr << _config.name << ": --yul-optimizations '" << sequence << ":"
			<< settings.yulOptimiserCleanupSteps << "' --optimize-runs "
			<< settings.expectedExecutionsPerDeployment << "\n";
	return settings;
}

/// With @param _variant, also the metamorphic variant of the sources (wrapInIdentityCalls)
static std::optional<CompilerOutput> compile(
	StringMap const& _sources,
	Config const& _config,
	util::h256 const& _seed = util::h256(),
	std::optional<StringMap>* _variant = nullptr
)
{
	CompilerInput input(
		evmVersion(_config),
		_sources,
		/*contractName=*/"",
		optimiserSettings(_config, _seed),
		{},
		/*debugFailure=*/false,
		_config.viaIR,
		_config.viaSSACFG
	);
	try
	{
		SolidityCompilationFramework framework(input);
		std::optional<CompilerOutput> output = framework.compileContract();
		if (!output && verbose())
			for (auto const& error: framework.compilerStack().errors())
				if (langutil::Error::isError(error->severity()))
				{
					std::cerr << "compile error: " << langutil::Error::formatErrorType(error->type()) << ": "
						<< (error->comment() ? *error->comment() : "") << "\n";
					break;
				}
#if !defined(AFL_MODE_ICE)
		if (output)
			if (auto const reason = afl::configDependentSemantics(
				framework.compilerStack(), s_legacyVsIR, s_legacyOptimizer))
			{
				stop("semantics: " + *reason);
				return std::nullopt;
			}
#endif
		if (output && _variant)
			*_variant = afl::wrapInIdentityCalls(framework.compilerStack(), _seed);
		return output;
	}
	// Known non-bugs in every mode. A diff below throws InternalCompilerError too, but outside this scope.
	catch (langutil::UnimplementedFeatureError const&) {}
	catch (langutil::StackTooDeepError const&) {}
	catch (evmasm::StackTooDeepException const&) {}
	catch (yul::StackTooDeepError const&) {}
	// afl-ts can produce non-UTF-8 bytes, which solc's JSON layer rejects
	catch (Json::exception const&) {}
#if defined(AFL_MODE_ICE)
	catch (langutil::InternalCompilerError const& _e)
	{
		if (std::string(_e.what()).find("FixedPointType not implemented") == std::string::npos)
		{
			// The throw site (file:line, function) is what triage buckets ICEs by
			std::cerr << boost::diagnostic_information(_e);
			throw;
		}
	}
	catch (boost::exception const& _e)
	{
		std::cerr << boost::diagnostic_information(_e);
		throw;
	}
#else
	// ICEs belong to the ICE mode
	catch (langutil::InternalCompilerError const&) {}
	catch (yul::YulAssertion const&) {}
	catch (yul::YulException const&) {}
#endif
	return std::nullopt;
}

/// One iteration. Any solAssert escapes so std::terminate aborts the persistent child and AFL records a crash.
static void runOneInput(std::string_view _input)
{
	yul::YulStringRepository::reset();

	if (_input.empty() || _input.size() > s_maxSourceBytes + s_maxCalldataBytes + 4)
		return;
	afl::AflInput const input = afl::splitInput(_input);
	if (input.source.empty() || input.source.size() > s_maxSourceBytes)
		return;
	// gas() / gasleft() differ by config. Substring matches on purpose: a false hit only costs one corpus entry. Inline
	// assembly is checked on the call graph after compiling (configDependentSemantics).
	if (input.source.find("gas()") != std::string::npos || input.source.find("gasleft") != std::string::npos)
		return stop("static: gas");
#if defined(AFL_MODE_ICE)
	if (input.source.find("assembly") != std::string::npos)
		return stop("static: assembly");
#endif
	// The compiled bytecode itself, which differs by config by design
	if (input.source.find("creationCode") != std::string::npos || input.source.find("runtimeCode") != std::string::npos)
		return stop("static: bytecode introspection");
#if defined(AFL_MODE_VIAIR)
	// via-IR always uses ABI coder v2, which validates inputs v1 accepts; isoltest marks tests whose
	// expectations hold for one codegen only
	if (input.source.find("abicoder v1") != std::string::npos || input.source.find("compileViaYul:") != std::string::npos)
		return stop("static: legacy-only test");
#endif
#if defined(AFL_MODE_EVMVERSION)
	// EIP-6780 (Cancun) changed what SELFDESTRUCT does
	if (input.source.find("selfdestruct") != std::string::npos)
		return stop("static: selfdestruct");
#endif
	std::optional<StringMap> const sources = afl::sourceUnits(input.source);
	if (!sources)
		return stop("static: source units");

#if defined(AFL_MODE_ICE)
	for (Config const& config: s_configs)
		compile(*sources, config);
#else
	auto const t0 = std::chrono::steady_clock::now();
	auto const ms = [](auto _from) {
		return std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - _from).count());
	};
#if defined(AFL_MODE_METAMORPHIC)
	std::optional<StringMap> variant;
	std::optional<CompilerOutput> outA = compile(*sources, s_configs[0], util::keccak256(input.source), &variant);
#else
	std::optional<CompilerOutput> outA = compile(*sources, s_configs[0]);
#endif
	if (verbose())
		std::cerr << "time: compile A " << ms(t0) << " ms\n";
	if (!outA)
		return stop("compile A");
	if (outA->byteCode.empty())
		return stop("no bytecode");
	auto const t1 = std::chrono::steady_clock::now();
#if defined(AFL_MODE_METAMORPHIC)
	if (!variant)
		return stop("nothing to wrap");
	if (verbose() && std::getenv("AFL_RUNNER_DUMP_VARIANT"))
		for (auto const& [name, source]: *variant)
			std::cerr << "==== Source: " << name << " ====\n" << source << "\n";
	std::optional<CompilerOutput> outB = compile(*variant, s_configs[1]);
#else
	std::optional<CompilerOutput> outB = compile(*sources, s_configs[1], util::keccak256(input.source));
#endif
	if (verbose())
		std::cerr << "time: compile B " << ms(t1) << " ms\n";
	if (!outB || outB->byteCode.empty())
		return stop("compile B");

	afl::CallPlan const plan = afl::planCalls(input, afl::interfaceOf(*outA));
	EVMHost hostA(evmVersion(s_configs[0]), evmone());
	EVMHost hostB(evmVersion(s_configs[1]), evmone());
	auto const t2 = std::chrono::steady_clock::now();
	afl::Execution execA = afl::execute(hostA, outA->byteCode, plan);
	afl::Execution execB = afl::execute(hostB, outB->byteCode, plan);
	if (verbose())
		std::cerr << "time: execute " << ms(t2) << " ms\n";
	if (std::getenv("AFL_RUNNER_VERBOSE"))
	{
		std::cerr << "deploy: " << execA.deployStatus << " / " << execB.deployStatus << "\n";
		for (std::size_t i = 0; i < plan.calls.size(); ++i)
			std::cerr << "call #" << i << " " << plan.calls[i].signature << ": "
				<< (i < execA.calls.size() ? std::to_string(execA.calls[i].status) : "-") << " / "
				<< (i < execB.calls.size() ? std::to_string(execB.calls[i].status) : "-")
				<< (i < execA.calls.size() && !execA.calls[i].subCalls.empty()
					? " (" + std::to_string(execA.calls[i].subCalls.size()) + " sub-calls)" : "")
				<< (std::getenv("AFL_RUNNER_VERBOSE") == std::string("2") ? " " + util::toHex(plan.calls[i].calldata) : "")
				<< "\n";
	}
	execA.state.storageLayouts = outA->storageLayoutByRuntimeCode;
	execB.state.storageLayouts = outB->storageLayoutByRuntimeCode;
	afl::Comparison const comparison = afl::compare(execA, execB);
	if (std::getenv("AFL_RUNNER_VERBOSE") && comparison.skipped)
		std::cerr << "not compared further: " << *comparison.skipped << "\n";
	solAssert(
		comparison.differences.empty(),
		std::string("Sol AFL diff fuzzer (") + s_configs[0].name + " vs " + s_configs[1].name + "): " +
			(comparison.differences.empty() ? "" : comparison.differences.front())
	);
#endif
}

int main(int argc, char** argv)
{
	// Explicit files bypass AFL (triage on host builds); several run in one process like persistent mode, for
	// profiling and for reproducing state carried between iterations
	if (argc >= 2)
	{
		for (int i = 1; i < argc; ++i)
			runOneInput(readFileAsString(argv[i]));
		return 0;
	}

	// Warm solc's and evmone's lazily initialized state into the forkserver image, so that a child running a single
	// iteration does not pay for it
	runOneInput("contract C { uint x; function f(uint a) external returns (uint) { x += a; return x * 2; } }");

	// Deferred forkserver: dlopen(libevmone) and static ctors of libsolc /
	// evmone run once per fork-server lifetime, not once per iteration.
	// Must come before the first AFL macro that touches the input buffer.
	__AFL_INIT();

	// Must be assigned before __AFL_LOOP — see persistent_demo_new.c.
	unsigned char const* buf = __AFL_FUZZ_TESTCASE_BUF;

	// AFL_RUNNER_LOOP=1 forks a fresh child per input: solc iterates pointer-keyed containers, so in a long-lived
	// persistent child the heap layout, and with it ~20% of the coverage, differs from run to run
	static unsigned const loops = [] {
		char const* env = std::getenv("AFL_RUNNER_LOOP");
		return env ? static_cast<unsigned>(std::max(1, std::atoi(env))) : 1000u;
	}();
	while (__AFL_LOOP(loops))
	{
		int len = __AFL_FUZZ_TESTCASE_LEN;  // do not inline into the call
		runOneInput(std::string_view(reinterpret_cast<char const*>(buf), static_cast<size_t>(len)));
	}

	return 0;
}
