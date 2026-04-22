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
#include <vector>

namespace solidity::test::solrecstructalias
{

namespace
{

/// Solidity type name for a given proto PrimType.
char const* solTypeName(PrimType _t)
{
	switch (_t)
	{
	case U8:      return "uint8";
	case U16:     return "uint16";
	case U32:     return "uint32";
	case U64:     return "uint64";
	case U128:    return "uint128";
	case U256:    return "uint256";
	case I256:    return "int256";
	case ADDRESS: return "address";
	case BOOL:    return "bool";
	case BYTES32: return "bytes32";
	}
	// unreachable; default keeps the compiler happy without an unnamed enum.
	return "uint256";
}

/// Emit a non-zero Solidity literal of the given type, derived from
/// (_seed + _fieldIdx + 1). Non-zero is important: writing zero and the
/// buggy-read-after-clear both produce zero, which would mask detection.
std::string literalFor(PrimType _t, uint64_t _seed, unsigned _fieldIdx)
{
	uint64_t v = _seed + _fieldIdx + 1;
	std::ostringstream hex;
	hex << "0x" << std::hex << v;
	std::string hexLit = hex.str();

	switch (_t)
	{
	case U8:
	case U16:
	case U32:
	case U64:
	case U128:
	case U256:
		// Hex literals are unsigned; cast narrows as needed. Solidity 0.8
		// requires an explicit cast from uint256 to narrower widths.
		return std::string(solTypeName(_t)) + "(uint256(" + hexLit + "))";
	case I256:
		return "int256(uint256(" + hexLit + "))";
	case ADDRESS:
		// uint160 cast then to address.
		return "address(uint160(" + hexLit + "))";
	case BOOL:
		// Deterministic from seed+idx; parity ensures both true/false appear.
		return ((v & 1u) != 0) ? "true" : "false";
	case BYTES32:
		return "bytes32(uint256(" + hexLit + "))";
	}
	return hexLit;
}

/// Default (zero) value in the given type. Used when we need to force a
/// distinguishing non-zero write: bool defaults to false, everything else
/// to 0, so if a bool's seed parity happened to yield false we pick true
/// instead. Only called by @ref literalForNonzeroBool.
bool defaultIsFalse(PrimType _t)
{
	return _t == BOOL;
}

/// Bool-specific: when we need a DEFINITELY non-default value. The bug
/// zeros every field — default for bool is `false`. If the seed happens to
/// pick `false`, we would fail to distinguish a correctly-written `false`
/// from a bug-zeroed `false`. This picks `true` unconditionally for bool.
std::string literalForWriteProbe(PrimType _t, uint64_t _seed, unsigned _fieldIdx)
{
	if (defaultIsFalse(_t))
		return "true";
	return literalFor(_t, _seed, _fieldIdx);
}

/// Copy a path's primitive fields to uint256 snap locals, and stage the
/// per-field mismatch checks the caller will emit AFTER the aliased copy.
/// Pure book-keeping to keep the main flow readable.
struct FieldDescriptor
{
	std::string name;   ///< e.g. "pre0", "suf1"
	PrimType type;
};

std::vector<FieldDescriptor> buildFieldList(
	std::vector<PrimType> const& _prefix,
	std::vector<PrimType> const& _suffix
)
{
	std::vector<FieldDescriptor> out;
	for (unsigned i = 0; i < _prefix.size(); i++)
		out.push_back({"pre" + std::to_string(i), _prefix[i]});
	for (unsigned i = 0; i < _suffix.size(); i++)
		out.push_back({"suf" + std::to_string(i), _suffix[i]});
	return out;
}

/// Truncate a repeated proto field to at most @p _max elements. Returns a
/// std::vector copy so downstream code has a stable container.
std::vector<PrimType> clampedTypes(
	::google::protobuf::RepeatedField<int> const& _in,
	unsigned _max
)
{
	std::vector<PrimType> out;
	unsigned n = std::min<unsigned>(static_cast<unsigned>(_in.size()), _max);
	for (unsigned i = 0; i < n; i++)
	{
		int raw = _in.Get(static_cast<int>(i));
		// Enum bounds check — libprotobuf-mutator can supply out-of-range
		// values. Anything outside the PrimType range collapses to U256.
		PrimType t = (raw >= U8 && raw <= BYTES32) ? static_cast<PrimType>(raw) : U256;
		out.push_back(t);
	}
	return out;
}

} // namespace

std::string ProtoConverter::protoToSolidity(Program const& _p)
{
	// --- grammar clamping ---
	std::vector<PrimType> prefix = clampedTypes(_p.struct_layout().prefix_types(), kMaxFieldsPerSide);
	std::vector<PrimType> suffix = clampedTypes(_p.struct_layout().suffix_types(), kMaxFieldsPerSide);
	m_primFieldCount = static_cast<unsigned>(prefix.size() + suffix.size());

	unsigned pushCount = std::max<unsigned>(1, std::min<unsigned>(_p.push_count(), kMaxPushes));
	unsigned childIdx = _p.child_index() % pushCount;

	AliasShape shape = _p.shape();
	if (shape < DIRECT || shape > GRANDCHILD)
		shape = DIRECT;

	unsigned grandPushes = std::max<unsigned>(1, std::min<unsigned>(_p.grandchild_push_count(), kMaxPushes));
	unsigned grandIdx = _p.grandchild_index() % grandPushes;

	uint64_t seed = _p.seed() ^ 0xA5A5A5A5A5A5A5A5ULL;

	std::vector<FieldDescriptor> fields = buildFieldList(prefix, suffix);

	// --- emit source ---
	std::ostringstream src;
	src << "// SPDX-License-Identifier: UNLICENSED\n";
	src << "pragma solidity >=0.8.0;\n";
	src << "\n";
	src << "contract C {\n";

	// Struct declaration. Field order: prefix primitives, children, suffix
	// primitives. Types chosen by the grammar so storage packing varies.
	src << "    struct Node {\n";
	for (unsigned i = 0; i < prefix.size(); i++)
		src << "        " << solTypeName(prefix[i]) << " pre" << i << ";\n";
	src << "        Node[] children;\n";
	for (unsigned i = 0; i < suffix.size(); i++)
		src << "        " << solTypeName(suffix[i]) << " suf" << i << ";\n";
	src << "    }\n";
	src << "\n";
	src << "    Node root;\n";
	src << "\n";
	src << "    function test() external returns (uint256 mask) {\n";

	// Helper: the Solidity path expression identifying the SOURCE struct
	// whose primitives we will snapshot and which is the RHS of the
	// aliased assignment.
	std::string srcPath;
	switch (shape)
	{
	case DIRECT:
	case VIA_POINTER:
		// Pushes on root.children
		for (unsigned i = 0; i < pushCount; i++)
			src << "        root.children.push();\n";
		srcPath = "root.children[" + std::to_string(childIdx) + "]";
		break;
	case GRANDCHILD:
		for (unsigned i = 0; i < pushCount; i++)
			src << "        root.children.push();\n";
		// Push onto root.children[childIdx].children grandPushes times.
		for (unsigned i = 0; i < grandPushes; i++)
			src << "        root.children[" << childIdx << "].children.push();\n";
		srcPath = "root.children[" + std::to_string(childIdx) +
			"].children[" + std::to_string(grandIdx) + "]";
		break;
	}

	// Write probe values into every primitive field of srcPath.
	for (unsigned i = 0; i < fields.size(); i++)
		src << "        " << srcPath << "." << fields[i].name
			<< " = " << literalForWriteProbe(fields[i].type, seed, i) << ";\n";

	// Snapshot every primitive field from srcPath BEFORE the aliased copy.
	// Types differ, so each snapshot is of the matching Solidity type.
	for (unsigned i = 0; i < fields.size(); i++)
		src << "        " << solTypeName(fields[i].type) << " snap" << i
			<< " = " << srcPath << "." << fields[i].name << ";\n";

	// Execute the shape-specific aliased assignment.
	switch (shape)
	{
	case DIRECT:
		src << "        root = " << srcPath << ";\n";
		break;
	case VIA_POINTER:
		src << "        Node storage p = " << srcPath << ";\n";
		src << "        root = p;\n";
		break;
	case GRANDCHILD:
		src << "        root = " << srcPath << ";\n";
		break;
	}

	// Compare each primitive field of root (the destination) to its snapshot.
	// Mismatch → set bit i of the returned mask.
	for (unsigned i = 0; i < fields.size(); i++)
		src << "        if (root." << fields[i].name << " != snap" << i
			<< ") mask |= " << (1ULL << i) << ";\n";

	src << "    }\n";
	src << "}\n";

	return src.str();
}

} // namespace solidity::test::solrecstructalias
