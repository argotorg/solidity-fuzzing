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
 * Standalone runner for the constant optimizer fuzzer target.
 * Reads a binary input file and runs it through testConstantOptimizer,
 * exactly as the ossfuzz target would, so performance can be analyzed
 * without the libFuzzer infrastructure.
 *
 * Usage: const_opt_runner <input-file>
 */

#include <tools/common/fuzzer_common.h>

#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char** argv)
{
	if (argc != 2)
	{
		std::cerr << "Usage: " << argv[0] << " <input-file>" << std::endl;
		return 1;
	}

	std::ifstream file(argv[1], std::ios::binary);
	if (!file)
	{
		std::cerr << "Error: cannot open file '" << argv[1] << "'" << std::endl;
		return 1;
	}

	std::string input{
		std::istreambuf_iterator<char>(file),
		std::istreambuf_iterator<char>()
	};

	FuzzerUtil::testConstantOptimizer(input, /*_quiet=*/false);

	return 0;
}
