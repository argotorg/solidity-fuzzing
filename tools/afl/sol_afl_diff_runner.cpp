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
#include <libsolutil/Keccak256.h>
#include <libsolutil/CommonData.h>
#include <libsolutil/CommonIO.h>
#include <libsolutil/JSON.h>

#include <boost/exception/diagnostic_information.hpp>

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

static constexpr int64_t s_gasLimit = 1000000;
/// afl-ts splices keep growing inputs; real-world corpus entries routinely exceed the proto fuzzer's 3 KB
static constexpr size_t s_maxSourceBytes = 16 * 1024;
static constexpr size_t s_maxCalldataBytes = 64 * 1024;

struct Config
{
	char const* name;
	bool viaIR;
	bool optimize;
	bool viaSSACFG = false;
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
#else
static constexpr Config s_configs[] = {{"legacy", false, false}, {"legacy-opt", false, true}};
#endif

static std::optional<CompilerOutput> compile(StringMap const& _sources, Config const& _config)
{
	CompilerInput input(
		langutil::EVMVersion::current(),
		_sources,
		/*contractName=*/"",
		_config.optimize ? OptimiserSettings::standard() : OptimiserSettings::minimal(),
		{},
		/*debugFailure=*/false,
		_config.viaIR,
		_config.viaSSACFG
	);
	try
	{
		return SolidityCompilationFramework(input).compileContract();
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
	// Inline assembly can break solc's invariants in ways that look like miscompiles; gas() differs by config.
	// Substring matches on purpose: a false hit only costs one corpus entry.
	if (input.source.find("assembly") != std::string::npos || input.source.find("gas()") != std::string::npos)
		return;
	// The compiled bytecode itself, which differs by config by design
	if (input.source.find("creationCode") != std::string::npos || input.source.find("runtimeCode") != std::string::npos)
		return;
#if defined(AFL_MODE_VIAIR)
	// via-IR always uses ABI coder v2, which validates inputs v1 accepts; isoltest also marks legacy-only tests
	if (input.source.find("abicoder v1") != std::string::npos || input.source.find("compileViaYul: false") != std::string::npos)
		return;
#endif
	std::optional<StringMap> const sources = afl::sourceUnits(input.source);
	if (!sources)
		return;

#if defined(AFL_MODE_ICE)
	for (Config const& config: s_configs)
		compile(*sources, config);
#else
	std::optional<CompilerOutput> outA = compile(*sources, s_configs[0]);
	if (!outA || outA->byteCode.empty())
		return;
	std::optional<CompilerOutput> outB = compile(*sources, s_configs[1]);
	if (!outB || outB->byteCode.empty())
		return;

	afl::CallPlan const plan = afl::planCalls(input, outA->methodIdentifiersInContract);
	langutil::EVMVersion const version = langutil::EVMVersion::current();
	EVMHost hostA(version, evmone());
	EVMHost hostB(version, evmone());
	afl::Execution execA = afl::execute(hostA, outA->byteCode, plan, s_gasLimit);
	afl::Execution execB = afl::execute(hostB, outB->byteCode, plan, s_gasLimit);
	if (std::getenv("AFL_RUNNER_VERBOSE"))
	{
		std::cerr << "deploy: " << execA.deployStatus << " / " << execB.deployStatus << "\n";
		for (std::size_t i = 0; i < plan.calls.size(); ++i)
			std::cerr << "call #" << i << " " << plan.calls[i].signature << ": "
				<< (i < execA.calls.size() ? std::to_string(execA.calls[i].status) : "-") << " / "
				<< (i < execB.calls.size() ? std::to_string(execB.calls[i].status) : "-") << "\n";
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
	// Repro / one-shot path: explicit filename bypasses AFL entirely so
	// `./sol_afl_diff_runner crash-xxxx` keeps working for triage on host
	// builds without an AFL runtime present.
	if (argc >= 2)
	{
		std::string input = readFileAsString(argv[1]);
		runOneInput(input);
		return 0;
	}

	// Deferred forkserver: dlopen(libevmone) and static ctors of libsolc /
	// evmone run once per fork-server lifetime, not once per iteration.
	// Must come before the first AFL macro that touches the input buffer.
	__AFL_INIT();

	// Must be assigned before __AFL_LOOP — see persistent_demo_new.c.
	unsigned char const* buf = __AFL_FUZZ_TESTCASE_BUF;

	// 1000 iterations between fork restarts amortises startup ~1000x; AFL
	// then re-forks to flush any slow leaks in solc/evmone. Recommended
	// starting point per AFL++ docs section 4.
	while (__AFL_LOOP(1000))
	{
		int len = __AFL_FUZZ_TESTCASE_LEN;  // do not inline into the call
		runOneInput(std::string_view(reinterpret_cast<char const*>(buf), static_cast<size_t>(len)));
	}

	return 0;
}
