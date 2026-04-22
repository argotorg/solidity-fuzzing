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

#include <tools/ossfuzz/solRecStructAliasProto.pb.h>

#include <cstdint>
#include <string>

namespace solidity::test::solrecstructalias
{

class ProtoConverter
{
public:
	ProtoConverter() = default;
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;

	/// Convert @p _p into a Solidity source that exercises the aliased
	/// storage struct-copy pattern.
	///
	/// Also populates @ref m_primFieldCount — the harness uses this to
	/// know how many low bits of the return value must be zero.
	std::string protoToSolidity(Program const& _p);

	/// Total number of primitive fields in the struct after grammar
	/// clamping (prefix + suffix). Valid after @ref protoToSolidity.
	/// The test function returns a uint256 bitmask with bit i set when
	/// primitive field i differs post-copy; only the low m_primFieldCount
	/// bits are meaningful.
	unsigned primitiveFieldCount() const { return m_primFieldCount; }

	/// Clamp limits. Kept small — the bug is expressible with one prefix
	/// and one suffix field, and tiny sources keep libFuzzer throughput up.
	static constexpr unsigned kMaxFieldsPerSide = 3;
	static constexpr unsigned kMaxPushes = 3;

private:
	unsigned m_primFieldCount = 0;
};

} // namespace solidity::test::solrecstructalias
