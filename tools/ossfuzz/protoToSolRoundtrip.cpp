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

#include <tools/ossfuzz/protoToSolRoundtrip.h>

#include <algorithm>
#include <sstream>
#include <string>

namespace solidity::test::solroundtrip
{

namespace
{

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
	return "uint256";
}

bool isInteger(PrimType _t)
{
	switch (_t)
	{
	case U8: case U16: case U32: case U64: case U128: case U256: case I256:
		return true;
	default:
		return false;
	}
}

/// Zero / default literal for the given type. `delete` on a storage var of
/// type T is required by the Solidity spec to produce exactly this value.
std::string zeroLit(PrimType _t)
{
	switch (_t)
	{
	case U8:      return "uint8(0)";
	case U16:     return "uint16(0)";
	case U32:     return "uint32(0)";
	case U64:     return "uint64(0)";
	case U128:    return "uint128(0)";
	case U256:    return "uint256(0)";
	case I256:    return "int256(0)";
	case ADDRESS: return "address(0)";
	case BOOL:    return "false";
	case BYTES32: return "bytes32(0)";
	}
	return "0";
}

/// Type-max literal. Solidity provides `type(T).max` for integer types and
/// `type(uintN).max` which we reuse for address (via uint160 cast) and
/// bytes32 (via uint256 cast).
std::string maxLit(PrimType _t)
{
	switch (_t)
	{
	case U8:      return "type(uint8).max";
	case U16:     return "type(uint16).max";
	case U32:     return "type(uint32).max";
	case U64:     return "type(uint64).max";
	case U128:    return "type(uint128).max";
	case U256:    return "type(uint256).max";
	case I256:    return "type(int256).max";
	case ADDRESS: return "address(type(uint160).max)";
	case BOOL:    return "true";
	case BYTES32: return "bytes32(type(uint256).max)";
	}
	return "0";
}

std::string oneLit(PrimType _t)
{
	switch (_t)
	{
	case U8:      return "uint8(1)";
	case U16:     return "uint16(1)";
	case U32:     return "uint32(1)";
	case U64:     return "uint64(1)";
	case U128:    return "uint128(1)";
	case U256:    return "uint256(1)";
	case I256:    return "int256(1)";
	case ADDRESS: return "address(uint160(1))";
	case BOOL:    return "true";
	case BYTES32: return "bytes32(uint256(1))";
	}
	return "1";
}

std::string derivedLit(PrimType _t, uint64_t _v)
{
	std::ostringstream hex;
	hex << "0x" << std::hex << _v;
	std::string h = hex.str();
	switch (_t)
	{
	case U8: case U16: case U32: case U64: case U128: case U256:
		return std::string(solTypeName(_t)) + "(uint256(" + h + "))";
	case I256:
		return "int256(uint256(" + h + "))";
	case ADDRESS:
		return "address(uint160(" + h + "))";
	case BOOL:
		return (_v & 1u) ? "true" : "false";
	case BYTES32:
		return "bytes32(uint256(" + h + "))";
	}
	return h;
}

/// Pick a literal for the probe's value. See the seed-bucketing comment on
/// `Probe.seed` in the proto file.
std::string literalForSeed(PrimType _t, uint64_t _seed)
{
	switch (_seed & 3u)
	{
	case 0: return zeroLit(_t);
	case 1: return maxLit(_t);
	case 2: return oneLit(_t);
	default: return derivedLit(_t, _seed >> 2);
	}
}

/// Pick an effective op given the input op and type. CAST_LADDER is
/// integer-only; anything else downgrades to ABI_ROUNDTRIP. That keeps the
/// generated-code type/op matrix minimal.
IdentityOp effectiveOp(IdentityOp _op, PrimType _t)
{
	if (_op < ABI_ROUNDTRIP || _op > CAST_LADDER)
		return ABI_ROUNDTRIP;
	if (_op == CAST_LADDER && !isInteger(_t))
		return ABI_ROUNDTRIP;
	return _op;
}

PrimType clampType(int _raw)
{
	return (_raw >= U8 && _raw <= BYTES32) ? static_cast<PrimType>(_raw) : U256;
}

IdentityOp clampOp(int _raw)
{
	return (_raw >= ABI_ROUNDTRIP && _raw <= CAST_LADDER)
		? static_cast<IdentityOp>(_raw) : ABI_ROUNDTRIP;
}

} // namespace

std::string ProtoConverter::protoToSolidity(Program const& _p)
{
	unsigned probeCount = std::min<unsigned>(
		static_cast<unsigned>(_p.probes_size()),
		kMaxProbes
	);
	m_probeCount = probeCount;

	std::ostringstream src;
	src << "// SPDX-License-Identifier: UNLICENSED\n";
	src << "pragma solidity >=0.8.0;\n";
	src << "\n";
	src << "contract C {\n";

	// One state var per probe. Only STORAGE_MEM_ROUND and DELETE_DEFAULT
	// use it, but declaring up front keeps the per-probe block simple.
	for (unsigned i = 0; i < probeCount; i++)
	{
		PrimType t = clampType(_p.probes(i).type());
		src << "    " << solTypeName(t) << " s" << i << ";\n";
	}
	src << "\n";

	src << "    function test() external returns (uint256 mask) {\n";

	for (unsigned i = 0; i < probeCount; i++)
	{
		Probe const& pr = _p.probes(i);
		PrimType t = clampType(pr.type());
		IdentityOp op = effectiveOp(clampOp(pr.op()), t);
		uint64_t seed = pr.seed();
		char const* tn = solTypeName(t);
		std::string val = literalForSeed(t, seed);
		uint64_t bit = 1ULL << i;

		src << "        // probe " << i << ": type=" << tn
			<< " op=" << static_cast<int>(op) << "\n";
		src << "        {\n";
		src << "            " << tn << " v = " << val << ";\n";

		switch (op)
		{
		case ABI_ROUNDTRIP:
			src << "            " << tn
				<< " r = abi.decode(abi.encode(v), (" << tn << "));\n";
			src << "            if (r != v) mask |= " << bit << ";\n";
			break;
		case STORAGE_MEM_ROUND:
			src << "            s" << i << " = v;\n";
			src << "            " << tn << " local = s" << i << ";\n";
			src << "            s" << i << " = local;\n";
			src << "            if (s" << i << " != v) mask |= " << bit << ";\n";
			break;
		case DELETE_DEFAULT:
			src << "            s" << i << " = v;\n";
			src << "            delete s" << i << ";\n";
			src << "            if (s" << i << " != " << zeroLit(t)
				<< ") mask |= " << bit << ";\n";
			break;
		case CAST_LADDER:
			// Integer-only (enforced by effectiveOp). Widen to uint256 then
			// narrow back — must be the identity for integer types.
			src << "            " << tn << " r = " << tn << "(uint256(v));\n";
			src << "            if (r != v) mask |= " << bit << ";\n";
			break;
		}

		src << "        }\n";
	}

	src << "    }\n";
	src << "}\n";

	return src.str();
}

} // namespace solidity::test::solroundtrip
