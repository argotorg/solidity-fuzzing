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

#include <tools/common/fuzzer_common.h>

#include <test/TestCaseReader.h>
#include <liblangutil/EVMVersion.h>

#include <sstream>

using namespace solidity::frontend::test;

static auto constexpr s_evmVersions = solidity::langutil::EVMVersion::allVersions();

// Prototype as we can't use the FuzzerInterface.h header.
extern "C" int LLVMFuzzerTestOneInput(uint8_t const* _data, size_t _size);

extern "C" int LLVMFuzzerTestOneInput(uint8_t const* _data, size_t _size)
{
	// We don't limit the `_size`, because it can be limited by the fuzzing engine's configuration
	// via `-max_len=N`
	std::string input(reinterpret_cast<char const*>(_data), _size);
	if (input.find("experimental") != std::string::npos)
	{
		// We are not interested in testing `pragma experimental` as it is not stable and may be removed
		return 0;
	}
	std::map<std::string, std::string> sourceCode;
	try
	{
		TestCaseReader t = TestCaseReader(std::istringstream(input));
		sourceCode = t.sources().sources;
		const bool compileViaYul = _size % 3 == 1;
		const bool optimize = _size % 2 == 0;
		const solidity::langutil::EVMVersion evmVersion = s_evmVersions[_size % s_evmVersions.size()];
		const bool forceSMT = false;
		FuzzerUtil::testCompiler(
			sourceCode,
			optimize,
			evmVersion,
			forceSMT,
			compileViaYul
		);
	}
	catch (std::runtime_error const&)
	{
		return 0;
	}
	return 0;
}
