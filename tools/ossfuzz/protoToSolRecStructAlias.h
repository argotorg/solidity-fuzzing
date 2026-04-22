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

#include <string>

namespace solidity::test::solrecstructalias
{

class ProtoConverter
{
public:
	ProtoConverter() = default;
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;

	/// Convert @p _p into a Solidity source that exercises one shape from
	/// the recursive-storage-struct aliasing family.
	///
	/// Also populates @ref m_primFieldCount — the harness uses it to know
	/// how many low bits of the returned bitmask are meaningful.
	std::string protoToSolidity(Program const& _p);

	/// Total number of primitive fields in the struct after grammar
	/// clamping (prefix + suffix). Valid after @ref protoToSolidity.
	unsigned primitiveFieldCount() const { return m_primFieldCount; }

	/// Clamp limits. The grammar is intentionally tight — the bug is
	/// reachable with 1 field and 1 push, but the fuzzer needs enough
	/// room to permute packing and index orderings.
	static constexpr unsigned kMaxFieldsPerSide = 3;
	static constexpr unsigned kMaxPushes = 3;

private:
	unsigned m_primFieldCount = 0;
};

} // namespace solidity::test::solrecstructalias
