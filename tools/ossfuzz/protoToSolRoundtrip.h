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

#include <tools/ossfuzz/solRoundtripProto.pb.h>

#include <string>

namespace solidity::test::solroundtrip
{

class ProtoConverter
{
public:
	ProtoConverter() = default;
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;

	/// Convert @p _p into a Solidity contract whose `test()` returns a
	/// bitmask: bit i is set iff the i-th probe's identity does not hold.
	std::string protoToSolidity(Program const& _p);

	/// Number of probes actually emitted after clamping. The harness uses
	/// this to confirm there is any oracle at all.
	unsigned probeCount() const { return m_probeCount; }

	/// Max probes per program. Higher → richer coverage per exec at the
	/// cost of slower compilation.
	static constexpr unsigned kMaxProbes = 4;

private:
	unsigned m_probeCount = 0;
};

} // namespace solidity::test::solroundtrip
