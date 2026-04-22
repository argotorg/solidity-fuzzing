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

#include <tools/ossfuzz/protoToSolRecStructAlias.h>

#include <algorithm>
#include <sstream>
#include <string>

namespace solidity::test::solrecstructalias
{

namespace
{

std::string uint256Hex(uint64_t _lo)
{
	// Non-zero 256-bit literal derived from _lo. Fits in uint256.
	// Using hex avoids the parser treating large decimals as signed.
	std::ostringstream oss;
	oss << "0x" << std::hex << _lo;
	return oss.str();
}

} // namespace

std::string ProtoConverter::protoToSolidity(Program const& _p)
{
	// --- clamp grammar ---
	unsigned prefixCount = std::min<unsigned>(_p.struct_layout().prefix_field_count(), kMaxFieldsPerSide);
	unsigned suffixCount = std::min<unsigned>(_p.struct_layout().suffix_field_count(), kMaxFieldsPerSide);
	m_primFieldCount = prefixCount + suffixCount;

	unsigned pushCount = std::max<unsigned>(1, std::min<unsigned>(_p.push_count(), kMaxPushes));
	unsigned childIdx = _p.child_index() % pushCount;

	// XOR-mask ensures a default-constructed Program (all zeros) still
	// yields nonzero values for every field.
	uint64_t seed = _p.seed() ^ 0xA5A5A5A5A5A5A5A5ULL;

	std::ostringstream src;
	src << "// SPDX-License-Identifier: UNLICENSED\n";
	src << "pragma solidity >=0.8.0;\n";
	src << "\n";
	src << "contract C {\n";

	// --- struct declaration: prefix primitives, children, suffix primitives ---
	src << "    struct Node {\n";
	for (unsigned i = 0; i < prefixCount; i++)
		src << "        uint256 pre" << i << ";\n";
	src << "        Node[] children;\n";
	for (unsigned i = 0; i < suffixCount; i++)
		src << "        uint256 suf" << i << ";\n";
	src << "    }\n";
	src << "\n";

	// --- state var ---
	src << "    Node root;\n";
	src << "\n";

	// --- test() ---
	src << "    function test() external returns (uint256 mask) {\n";

	// push children
	for (unsigned i = 0; i < pushCount; i++)
		src << "        root.children.push();\n";

	// write primitives into root.children[childIdx]. Field-index numbering
	// is: prefix first, then suffix. Values are seed + index + 1.
	unsigned fieldIndex = 0;
	for (unsigned i = 0; i < prefixCount; i++)
	{
		src << "        root.children[" << childIdx << "].pre" << i
			<< " = " << uint256Hex(seed + fieldIndex + 1) << ";\n";
		fieldIndex++;
	}
	for (unsigned i = 0; i < suffixCount; i++)
	{
		src << "        root.children[" << childIdx << "].suf" << i
			<< " = " << uint256Hex(seed + fieldIndex + 1) << ";\n";
		fieldIndex++;
	}

	// Snapshot every primitive field from the child (pre-copy) into a local.
	// These reads happen BEFORE the aliased assignment, so they must match
	// the values written above regardless of the bug.
	fieldIndex = 0;
	for (unsigned i = 0; i < prefixCount; i++)
	{
		src << "        uint256 snap" << fieldIndex
			<< " = root.children[" << childIdx << "].pre" << i << ";\n";
		fieldIndex++;
	}
	for (unsigned i = 0; i < suffixCount; i++)
	{
		src << "        uint256 snap" << fieldIndex
			<< " = root.children[" << childIdx << "].suf" << i << ";\n";
		fieldIndex++;
	}

	// --- the trigger: storage-to-storage assignment from a descendant of
	//     the destination. Report #1392: legacy codegen (LValue.cpp:387) and
	//     IR codegen (YulUtilFunctions.cpp:3762/1966) both clear the
	//     children array before reading the other members, zeroing fields
	//     whose storage sat inside the cleared region.
	src << "        root = root.children[" << childIdx << "];\n";

	// Post-copy comparisons. Each mismatch sets one bit. Bit ordering
	// matches snapN ordering (prefix fields, then suffix fields).
	fieldIndex = 0;
	for (unsigned i = 0; i < prefixCount; i++)
	{
		src << "        if (root.pre" << i << " != snap" << fieldIndex
			<< ") mask |= " << (1ULL << fieldIndex) << ";\n";
		fieldIndex++;
	}
	for (unsigned i = 0; i < suffixCount; i++)
	{
		src << "        if (root.suf" << i << " != snap" << fieldIndex
			<< ") mask |= " << (1ULL << fieldIndex) << ";\n";
		fieldIndex++;
	}

	src << "    }\n";
	src << "}\n";

	return src.str();
}

} // namespace solidity::test::solrecstructalias
