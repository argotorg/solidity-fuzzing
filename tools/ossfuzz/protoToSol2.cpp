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

#include <tools/ossfuzz/protoToSol2.h>

#include <algorithm>
#include <set>

using namespace solidity::test::sol2protofuzzer;

// =====================================================================
// Top-level
// =====================================================================

std::string ProtoConverter::protoToSolidity(Program const& _p)
{
	m_randomGen = std::make_shared<SolRandomNumGenerator>(
		static_cast<unsigned>(_p.seed())
	);
	return visit(_p);
}

std::string ProtoConverter::visit(Program const& _p)
{
	// Pre-process: create ContractInfo for each contract
	unsigned numContracts = std::min(
		static_cast<unsigned>(_p.contracts_size()),
		s_maxContracts
	);

	for (unsigned i = 0; i < numContracts; i++)
	{
		auto const& c = _p.contracts(i);
		ContractInfo info;
		info.name = "C" + std::to_string(i);
		// Normalize kind: anything that isn't LIBRARY is treated as CONTRACT
		info.kind = (c.kind() == ContractDef::LIBRARY) ? ContractDef::LIBRARY : ContractDef::CONTRACT;

		// Functions — use unique names to avoid conflicts with inheritance.
		// Overloading: if share_name_with_prev is set, reuse the previous
		// function's name (with a forced-different param count).
		unsigned numFuncs = std::min(
			static_cast<unsigned>(c.functions_size()),
			s_maxFunctions
		);
		// Non-library contracts need at least one public function so the
		// test contract can call it. Inject one if the proto has none.
		if (numFuncs == 0 && info.kind != ContractDef::LIBRARY)
		{
			FuncInfo fi;
			fi.name = "f" + std::to_string(i) + "_0";
			fi.numParams = 1;
			fi.paramTypes.push_back(PARAM_UINT256);
			fi.vis = PUBLIC;
			fi.mut = PURE;
			info.functions.push_back(fi);
		}
		for (unsigned j = 0; j < numFuncs; j++)
		{
			FuncInfo fi;
			fi.name = "f" + std::to_string(i) + "_" + std::to_string(j);
			fi.numParams = std::max(1u, std::min(
				static_cast<unsigned>(c.functions(j).num_params()),
				s_maxParams
			));
			fi.vis = c.functions(j).vis();
			fi.mut = c.functions(j).mut();
			// Populate per-parameter types from proto (default: PARAM_UINT256)
			for (unsigned p = 0; p < fi.numParams; p++)
			{
				if (p < static_cast<unsigned>(c.functions(j).param_types_size()))
					fi.paramTypes.push_back(c.functions(j).param_types(p));
				else
					fi.paramTypes.push_back(PARAM_UINT256);
			}

			// Multiple return values
			fi.returnTwo = c.functions(j).has_returns_two() && c.functions(j).returns_two();

			// Non-virtual toggle (cannot be overridden in derived contracts)
			fi.nonVirtual = c.functions(j).has_non_virtual() && c.functions(j).non_virtual();

			// Force the first function of non-library contracts to be
			// PUBLIC so the test contract can always call at least one.
			if (j == 0 && info.kind != ContractDef::LIBRARY)
				fi.vis = PUBLIC;

			// Function overloading: share name with previous function
			if (j > 0 && c.functions(j).has_share_name_with_prev() &&
				c.functions(j).share_name_with_prev())
			{
				auto const& prev = info.functions[j - 1];
				// Only overload if param counts differ (same name + same
				// param count = duplicate signature, which is invalid)
				if (fi.numParams != prev.numParams)
					fi.name = prev.name;
				// If param counts match, force a different count
				else
				{
					fi.numParams = (prev.numParams % s_maxParams) + 1;
					if (fi.numParams == prev.numParams)
						fi.numParams = (fi.numParams % s_maxParams) + 1;
					fi.name = prev.name;
					// Rebuild paramTypes for new numParams
					fi.paramTypes.clear();
					for (unsigned p = 0; p < fi.numParams; p++)
					{
						if (p < static_cast<unsigned>(c.functions(j).param_types_size()))
							fi.paramTypes.push_back(c.functions(j).param_types(p));
						else
							fi.paramTypes.push_back(PARAM_UINT256);
					}
				}
			}

			info.functions.push_back(fi);
		}

		// Struct definitions
		unsigned numStructs = std::min(
			static_cast<unsigned>(c.structs_size()),
			s_maxStructs
		);
		for (unsigned j = 0; j < numStructs; j++)
		{
			StructDefInfo sdi;
			sdi.name = "S" + std::to_string(i) + "_" + std::to_string(j);
			unsigned numFields = std::max(1u, std::min(
				static_cast<unsigned>(c.structs(j).fields_size()),
				s_maxStructFields
			));
			for (unsigned k = 0; k < numFields; k++)
			{
				StructFieldInfo sfi;
				sfi.name = "f" + std::to_string(k);
				if (k < static_cast<unsigned>(c.structs(j).fields_size()))
				{
					auto const& sf = c.structs(j).fields(k);
					// Non-elementary override: arrays / function types.
					// Leaves the field non-uint-compatible so access code
					// never emits reads — only the declaration matters
					// for the targeted ICE paths.
					if (sf.has_arr_field())
					{
						auto const& af = sf.arr_field();
						std::string base = elementaryTypeStr(af.base());
						if (base == "string" || base == "bytes")
							base = "uint256";
						std::string ty = base;
						if (af.has_inner_length())
							ty += "[" + arraySizeBucket(af.inner_length()).first + "]";
						if (af.has_outer_length())
							ty += "[" + arraySizeBucket(af.outer_length()).first + "]";
						else
							ty += "[]";
						sfi.typeStr = ty;
						sfi.isUintCompatible = false;
					}
					else if (sf.has_fn_field())
					{
						auto const& ff = sf.fn_field();
						std::string ret =
							ff.has_returns_calldata_array() && ff.returns_calldata_array()
								? " returns (uint256[] calldata)" : "";
						sfi.typeStr = "function() external" + ret;
						sfi.isUintCompatible = false;
					}
					else
					{
						auto const& ft = sf.type();
						sfi.typeStr = elementaryTypeStr(ft);
						sfi.isUintCompatible = isUintType(ft);
						// Avoid dynamic types in structs to keep things simple
						if (sfi.typeStr == "string" || sfi.typeStr == "bytes")
						{
							sfi.typeStr = "uint256";
							sfi.isUintCompatible = true;
						}
					}
				}
				else
				{
					sfi.typeStr = "uint256";
					sfi.isUintCompatible = true;
				}
				sdi.fields.push_back(sfi);
			}
			info.structDefs.push_back(sdi);
		}

		// Enum definitions
		unsigned numEnums = std::min(
			static_cast<unsigned>(c.enums_size()),
			s_maxEnums
		);
		for (unsigned j = 0; j < numEnums; j++)
		{
			EnumDefInfo edi;
			edi.name = "E" + std::to_string(i) + "_" + std::to_string(j);
			edi.numMembers = std::max(1u, std::min(
				c.enums(j).num_members(),
				static_cast<uint32_t>(s_maxEnumMembers)
			));
			for (unsigned k = 0; k < edi.numMembers; k++)
				edi.memberNames.push_back(edi.name + "_m" + std::to_string(k));
			info.enumDefs.push_back(edi);
		}

		// State variables — use unique names
		unsigned numSV = std::min(
			static_cast<unsigned>(c.state_vars_size()),
			s_maxStateVars
		);
		for (unsigned j = 0; j < numSV; j++)
		{
			auto const& sv = c.state_vars(j);
			StateVarInfo svi;
			svi.name = "sv" + std::to_string(i) + "_" + std::to_string(j);

			if (sv.type().type_oneof_case() == TypeName::kArray)
			{
				auto const& arr = sv.type().array();
				svi.typeStr = elementaryTypeStr(sv.type());
				svi.isArray = true;
				// An expression-valued size makes the array declaration
				// fixed-syntactically (the parser sees `T[expr]`), but the
				// runtime modulus must stay 1 — the expression is never a
				// real constant, so any runtime index must clamp to 0.
				bool hasExprSize = arr.has_size_expr()
					&& arr.size_expr().kind() != ArraySizeExpr::BUCKET;
				svi.isFixedArray = arr.has_length() || hasExprSize;
				if (hasExprSize)
					svi.arrayLength = 1;
				else if (arr.has_length())
					svi.arrayLength = arraySizeBucket(arr.length()).second;
				svi.elementIsUint = isUintType(arr.base());
			}
			else if (sv.type().type_oneof_case() == TypeName::kMapping)
			{
				auto const& map = sv.type().mapping();
				svi.typeStr = elementaryTypeStr(sv.type());
				svi.isMapping = true;
				svi.elementIsUint = isUintType(map.value());
				std::string keyType = elementaryTypeStr(map.key());
				if (keyType == "string" || keyType == "bytes")
					keyType = "uint256";
				if (keyType == "address payable")
					keyType = "address";
				svi.mappingKeyTypeStr = keyType;
			}
			// Check if this is a struct type
			else if (sv.type().type_oneof_case() == TypeName::kStructRef && !info.structDefs.empty())
			{
				unsigned structIdx = sv.type().struct_ref() % info.structDefs.size();
				svi.typeStr = info.structDefs[structIdx].name;
				svi.isStruct = true;
				svi.structDefIdx = structIdx;
			}
			else
			{
				svi.typeStr = elementaryTypeStr(sv.type());
				svi.isUint = isUintType(sv.type());
				// transient/constant/immutable only work with value types
				// (not arrays, mappings, structs, string, or bytes).
				// They are mutually exclusive: pick the first one set.
				// constant/immutable further restricted to uint types for
				// safe literal initialization (bool/address casts are tricky).
				bool isValueType = svi.typeStr != "string" && svi.typeStr != "bytes";
				if (isValueType)
				{
					if (svi.isUint && sv.has_is_constant() && sv.is_constant())
						svi.isConstant = true;
					else if (svi.isUint && sv.has_is_immutable() && sv.is_immutable())
						svi.isImmutable = true;
					else if (sv.has_is_transient() && sv.is_transient())
						svi.isTransient = true;
				}
			}
			info.stateVars.push_back(svi);
		}

		// Events
		unsigned numEv = std::min(
			static_cast<unsigned>(c.events_size()),
			s_maxEvents
		);
		for (unsigned j = 0; j < numEv; j++)
		{
			EventInfo ei;
			ei.name = "Ev" + std::to_string(i) + "_" + std::to_string(j);
			ei.numParams = std::min(
				static_cast<unsigned>(c.events(j).num_params()),
				s_maxEventParams
			);
			if (ei.numParams == 0)
				ei.numParams = 1;
			// Populate indexed flags (max 3 indexed per event)
			unsigned indexedCount = 0;
			for (unsigned k = 0; k < ei.numParams; k++)
			{
				bool isIndexed = false;
				if (k < static_cast<unsigned>(c.events(j).indexed_params_size()) &&
					c.events(j).indexed_params(k) && indexedCount < 3)
				{
					isIndexed = true;
					indexedCount++;
				}
				ei.indexedParams.push_back(isIndexed);
			}
			info.events.push_back(ei);
		}

		// Errors
		unsigned numErr = std::min(
			static_cast<unsigned>(c.errors_size()),
			s_maxErrors
		);
		for (unsigned j = 0; j < numErr; j++)
		{
			ErrorInfo eri;
			eri.name = "Err" + std::to_string(i) + "_" + std::to_string(j);
			eri.numParams = std::min(
				static_cast<unsigned>(c.errors(j).num_params()),
				s_maxErrorParams
			);
			if (eri.numParams == 0)
				eri.numParams = 1;
			for (unsigned k = 0; k < eri.numParams; k++)
				eri.paramNames.push_back("ep_" + std::to_string(j) + "_" + std::to_string(k));
			info.errors.push_back(eri);
		}

		// Modifiers
		unsigned numMod = std::min(
			static_cast<unsigned>(c.modifiers_size()),
			s_maxModifiers
		);
		for (unsigned j = 0; j < numMod; j++)
		{
			ModifierInfo mi;
			mi.name = "mod" + std::to_string(i) + "_" + std::to_string(j);
			info.modifiers.push_back(mi);
		}

		info.hasReceive = c.has_receive();
		info.hasFallback = c.has_fallback_func();
		info.hasCtorParam = c.has_constructor() && c.constructor().has_has_param() && c.constructor().has_param();

		m_contracts.push_back(info);
	}

	// Struct-param/return fixup pass: validate PARAM_STRUCT entries and
	// the returns_struct flag against contract scope (only honored for
	// internal/private functions — external/public ABI encoding would
	// require flattening, which the harness doesn't do). Falls back to
	// PARAM_UINT256 / no-op when the contract has no eligible struct
	// (first struct with a uint-compatible first field).
	for (unsigned i = 0; i < numContracts; i++)
	{
		auto const& c = _p.contracts(i);
		auto& info = m_contracts[i];

		std::string structName;
		unsigned structFieldCount = 0;
		for (auto const& sd : info.structDefs)
		{
			if (!sd.fields.empty() && sd.fields[0].isUintCompatible)
			{
				structName = sd.name;
				structFieldCount = static_cast<unsigned>(sd.fields.size());
				break;
			}
		}

		unsigned numFuncs = std::min(
			static_cast<unsigned>(c.functions_size()),
			s_maxFunctions
		);
		for (unsigned j = 0; j < numFuncs && j < info.functions.size(); j++)
		{
			auto& fi = info.functions[j];
			bool eligibleScope =
				(fi.vis == INTERNAL || fi.vis == PRIVATE) && !structName.empty();

			// Downgrade PARAM_STRUCT entries when out-of-scope.
			if (!eligibleScope)
			{
				for (auto& pt : fi.paramTypes)
					if (pt == PARAM_STRUCT)
						pt = PARAM_UINT256;
			}

			// Returns-struct: only honored for internal/private; also
			// clear returnTwo (single struct return is the only shape).
			auto const& fp = c.functions(j);
			bool wantsStructReturn =
				fp.has_returns_struct() && fp.returns_struct();
			if (wantsStructReturn && eligibleScope)
			{
				fi.returnsStruct = true;
				fi.returnTwo = false;
			}

			bool usesStruct = fi.returnsStruct;
			for (auto pt : fi.paramTypes)
				if (pt == PARAM_STRUCT) { usesStruct = true; break; }
			if (usesStruct)
			{
				fi.structParamTypeName = structName;
				fi.structParamFieldCount = structFieldCount;
			}
		}
	}

	// Process inheritance: a contract can inherit from up to 2 bases with lower index.
	// Diamond inheritance is prevented by checking that no two bases share an ancestor.
	for (unsigned i = 0; i < numContracts; i++)
	{
		auto const& c = _p.contracts(i);
		auto& info = m_contracts[i];

		if (info.kind != ContractDef::LIBRARY && i > 0 && c.bases_size() > 0)
		{
			// Helper: collect all ancestors of a contract (including itself)
			auto collectAncestors = [&](unsigned idx) -> std::set<unsigned>
			{
				std::set<unsigned> anc;
				std::vector<unsigned> stack = {idx};
				while (!stack.empty())
				{
					unsigned cur = stack.back();
					stack.pop_back();
					if (!anc.insert(cur).second)
						continue;
					for (unsigned b : m_contracts[cur].baseIndices)
						stack.push_back(b);
				}
				return anc;
			};

			std::set<unsigned> usedAncestors;
			unsigned maxBases = std::min(static_cast<unsigned>(c.bases_size()), 2u);
			for (unsigned b = 0; b < maxBases; b++)
			{
				unsigned candidateIdx = c.bases(b) % i;
				auto const& candidate = m_contracts[candidateIdx];
				if (candidate.kind == ContractDef::LIBRARY)
					continue;

				// Check no diamond: candidate's ancestor set must not
				// overlap with any already-chosen base's ancestors.
				auto candidateAnc = collectAncestors(candidateIdx);
				bool overlap = false;
				for (unsigned a : candidateAnc)
					if (usedAncestors.count(a))
					{
						overlap = true;
						break;
					}
				if (!overlap)
				{
					info.baseIndices.push_back(candidateIdx);
					usedAncestors.insert(candidateAnc.begin(), candidateAnc.end());
				}
			}
		}
	}

	// Resolve override_base: for each FunctionDef flagged with
	// override_base, walk the contract's base chain, collect virtual
	// non-private functions, and copy a chosen one's name/signature onto
	// the derived FuncInfo so emission produces a valid override.
	for (unsigned i = 0; i < numContracts; i++)
	{
		auto const& c = _p.contracts(i);
		auto& info = m_contracts[i];
		if (info.kind == ContractDef::LIBRARY)
			continue;
		if (info.baseIndices.empty())
			continue;

		// BFS the base chain to collect overridable candidates.
		std::vector<FuncInfo> candidates;
		std::vector<unsigned> visitedB;
		std::vector<unsigned> queueB(info.baseIndices.begin(), info.baseIndices.end());
		while (!queueB.empty())
		{
			unsigned bIdx = queueB.front();
			queueB.erase(queueB.begin());
			bool seen = false;
			for (unsigned v : visitedB)
				if (v == bIdx) { seen = true; break; }
			if (seen)
				continue;
			visitedB.push_back(bIdx);
			auto const& baseInfo = m_contracts[bIdx];
			for (auto const& bfi : baseInfo.functions)
			{
				if (bfi.vis == PRIVATE) continue;
				if (bfi.nonVirtual) continue;
				// Skip struct-using base functions: struct types are
				// named per-contract and the override would need to
				// reference the base's struct by inherited name, which
				// we don't wire through here.
				if (bfi.returnsStruct) continue;
				bool hasStruct = false;
				for (auto pt : bfi.paramTypes)
					if (pt == PARAM_STRUCT) { hasStruct = true; break; }
				if (hasStruct) continue;
				candidates.push_back(bfi);
			}
			for (unsigned bb : baseInfo.baseIndices)
				queueB.push_back(bb);
		}

		if (candidates.empty())
			continue;

		unsigned numFuncs2 = std::min(
			static_cast<unsigned>(c.functions_size()),
			s_maxFunctions
		);
		for (unsigned j = 0; j < numFuncs2 && j < info.functions.size(); j++)
		{
			auto const& fp = c.functions(j);
			if (!(fp.has_override_base() && fp.override_base()))
				continue;
			auto const& chosen = candidates[j % candidates.size()];
			// Skip if this contract already has a function with that name
			// and same param count (would cause duplicate-signature error).
			bool dup = false;
			for (unsigned k = 0; k < info.functions.size(); k++)
			{
				if (k == j) continue;
				auto const& other = info.functions[k];
				if (other.name == chosen.name && other.numParams == chosen.numParams)
				{
					dup = true;
					break;
				}
			}
			if (dup)
				continue;

			auto& fi = info.functions[j];
			fi.name = chosen.name;
			fi.numParams = chosen.numParams;
			fi.paramTypes = chosen.paramTypes;
			fi.returnTwo = chosen.returnTwo;
			fi.vis = chosen.vis;
			fi.mut = chosen.mut;
			fi.isOverride = true;
			// An overriding function must itself be virtual if further
			// derived contracts are to override it. Leave nonVirtual as-is:
			// the user's proto choice dictates whether the chain continues.
		}
	}

	// CREATE2 salt
	if (_p.has_create2_salt())
	{
		m_useCreate2 = true;
		// Pad or truncate to 32 bytes, then hex-encode
		std::string saltBytes(_p.create2_salt().begin(), _p.create2_salt().end());
		saltBytes.resize(32, '\0');
		m_create2SaltHex.clear();
		for (unsigned char c : saltBytes)
		{
			static char const hex[] = "0123456789abcdef";
			m_create2SaltHex += hex[c >> 4];
			m_create2SaltHex += hex[c & 0xf];
		}
	}

	// Pre-process free functions
	unsigned numFreeFuncs = std::min(
		static_cast<unsigned>(_p.free_functions_size()),
		s_maxFreeFunctions
	);
	m_freeFunctions.clear();
	// Check if we should generate UDVT (needed early: gates UDVT-sig free functions)
	m_hasUdvt = _p.has_gen_udvt() && _p.gen_udvt();

	for (unsigned i = 0; i < numFreeFuncs; i++)
	{
		FreeFuncInfo ffi;
		ffi.name = "ff" + std::to_string(i);
		ffi.numParams = std::min(
			static_cast<unsigned>(_p.free_functions(i).num_params()),
			s_maxParams
		);
		ffi.emitExternal =
			_p.free_functions(i).has_emit_external() &&
			_p.free_functions(i).emit_external();
		// UDVT-sig requires the UDVT itself to be emitted; ignore otherwise.
		ffi.useUdvtSig = m_hasUdvt
			&& _p.free_functions(i).has_use_udvt_sig()
			&& _p.free_functions(i).use_udvt_sig();
		// `external` on a UDVT-sig function would disable the
		// self-referential `a + b` body (external free funcs are the
		// #16620 shape, not #16616). Prefer the UDVT shape when both set.
		if (ffi.useUdvtSig)
			ffi.emitExternal = false;
		m_freeFunctions.push_back(ffi);
	}

	// Generate source
	std::ostringstream o;
	o << "// SPDX-License-Identifier: GPL-3.0\n";
	o << "pragma solidity >=0.0;\n\n";

	// Generate UDVT and operator functions if enabled
	if (m_hasUdvt)
	{
		o << "type MyUint is uint256;\n\n";
		// Free functions for user-defined operators
		o << "function _udvtAdd(MyUint a, MyUint b) pure returns (MyUint) {\n";
		o << "\treturn MyUint.wrap(MyUint.unwrap(a) + MyUint.unwrap(b));\n";
		o << "}\n";
		o << "function _udvtSub(MyUint a, MyUint b) pure returns (MyUint) {\n";
		o << "\treturn MyUint.wrap(MyUint.unwrap(a) - MyUint.unwrap(b));\n";
		o << "}\n";
		o << "function _udvtMul(MyUint a, MyUint b) pure returns (MyUint) {\n";
		o << "\treturn MyUint.wrap(MyUint.unwrap(a) * MyUint.unwrap(b));\n";
		o << "}\n";
		o << "function _udvtEq(MyUint a, MyUint b) pure returns (bool) {\n";
		o << "\treturn MyUint.unwrap(a) == MyUint.unwrap(b);\n";
		o << "}\n";
		o << "function _udvtLt(MyUint a, MyUint b) pure returns (bool) {\n";
		o << "\treturn MyUint.unwrap(a) < MyUint.unwrap(b);\n";
		o << "}\n\n";
		// Bind operators to the UDVT
		o << "using {_udvtAdd as +, _udvtSub as -, _udvtMul as *, _udvtEq as ==, _udvtLt as <} for MyUint global;\n\n";
	}

	// Generate free functions (file-level, implicitly internal, pure —
	// except when `emit_external` is set, which emits the invalid
	// `external` modifier to trip the frontend ICE on `using for`).
	for (unsigned i = 0; i < numFreeFuncs; i++)
	{
		auto const& ffi = m_freeFunctions[i];

		// UDVT-sig variant emits a fixed signature and body — no proto body
		// replay, no scope/state setup for expression generation. The body
		// uses `a + b` on MyUint operands so it resolves through the bound
		// `+` operator; when the user-level using-for directive adds a
		// duplicate `as +` binding on MyUint, #16616 ICEs.
		if (ffi.useUdvtSig)
		{
			o << "function " << ffi.name
			  << "(MyUint a, MyUint b) pure returns (MyUint) {\n"
			  << "\tMyUint c = a + b;\n"
			  << "\treturn c;\n"
			  << "}\n\n";
			continue;
		}

		o << "function " << ffi.name << "(";
		for (unsigned p = 0; p < ffi.numParams; p++)
		{
			if (p > 0) o << ", ";
			o << "uint256 p" << p;
		}
		if (ffi.emitExternal)
			o << ") external pure returns (uint256) {\n";
		else
			o << ") pure returns (uint256) {\n";

		// Set up state for free function body: pure, no state access
		m_canReadState = false;
		m_currentMutability = PURE;
		m_inConstructor = false;
		m_inFreeFunction = true;
		m_canReturn = true;
		m_currentReturnsTwo = false;
		m_currentStructReturnType.clear();
		m_currentStructReturnFieldCount = 0;
		m_currentFuncIdx = i;
		// Mark as not inside any contract
		m_currentContract = static_cast<unsigned>(m_contracts.size());
		// Clear contract-level state
		m_currentUintStateVars.clear();
		m_currentStructStateVars.clear();
		m_currentIndexableVars.clear();
		m_currentDynArrayVars.clear();
		m_currentEvents.clear();
		m_currentErrors.clear();
		m_currentStructDefs.clear();
		m_currentEnumDefs.clear();

		pushScope();
		m_localVarCount = 0;
		m_varCounter = 0;
		for (unsigned p = 0; p < ffi.numParams; p++)
			addVar("p" + std::to_string(p));
		m_indentLevel = 1;
		m_stmtDepth = 0;
		o << visitBlock(_p.free_functions(i).body());
		popScope();

		o << "\treturn 0;\n";
		o << "}\n\n";
		m_inFreeFunction = false;
	}

	// File-level `using {...} for T [global];` directives. Deliberately
	// emitted without validation so the frontend's using-for analysis has
	// to cope with zero-param operator bindings, duplicate bindings, and
	// wrong-target-type combinations (#16613, #16616).
	if (_p.file_using_for_size() > 0)
	{
		for (int i = 0; i < _p.file_using_for_size(); i++)
			o << emitUsingFor(_p.file_using_for(i), /*fileLevel*/ true);
		o << "\n";
	}

	// Generate contracts
	for (unsigned i = 0; i < numContracts; i++)
		o << visitContract(_p.contracts(i), i) << "\n";

	// Generate test contract
	o << generateTestContract();

	return o.str();
}

// =====================================================================
// Contract generation
// =====================================================================

std::string ProtoConverter::visitContract(ContractDef const& _c, unsigned _idx)
{
	auto const& info = m_contracts[_idx];
	m_usedCdl = false;
	m_usedCds = false;
	m_currentContract = _idx;

	bool isLibrary = (info.kind == ContractDef::LIBRARY);

	std::ostringstream o;

	// Contract header with optional inheritance
	if (isLibrary)
		o << "library " << info.name << " {\n";
	else if (!info.baseIndices.empty())
	{
		o << "contract " << info.name << " is ";
		for (unsigned b = 0; b < info.baseIndices.size(); b++)
		{
			if (b > 0) o << ", ";
			o << m_contracts[info.baseIndices[b]].name;
		}
		o << " {\n";
	}
	else
		o << "contract " << info.name << " {\n";

	// Struct definitions
	for (auto const& sd : info.structDefs)
	{
		o << "\tstruct " << sd.name << " {\n";
		for (auto const& sf : sd.fields)
			o << "\t\t" << sf.typeStr << " " << sf.name << ";\n";
		o << "\t}\n";
	}
	if (!info.structDefs.empty())
		o << "\n";

	// Enum definitions
	for (auto const& ed : info.enumDefs)
	{
		o << "\tenum " << ed.name << " {\n";
		for (unsigned k = 0; k < ed.numMembers; k++)
		{
			o << "\t\t" << ed.memberNames[k];
			if (k + 1 < ed.numMembers)
				o << ",";
			o << "\n";
		}
		o << "\t}\n";
	}
	if (!info.enumDefs.empty())
		o << "\n";

	// `using LibName for uint256;` declarations — attach library functions
	// as member functions on uint256 values, testing the using-for codepath.
	if (!isLibrary)
	{
		for (auto const& ci : m_contracts)
		{
			if (ci.kind != ContractDef::LIBRARY)
				continue;
			// Only emit using-for if the library has at least one function
			// with >= 1 param (the first param becomes the receiver).
			bool hasCallable = false;
			for (auto const& lf : ci.functions)
				if (lf.numParams >= 1)
				{
					hasCallable = true;
					break;
				}
			if (hasCallable)
				o << "\tusing " << ci.name << " for uint256;\n";
		}
	}

	// Proto-driven contract-scope using-for directives. Emitted verbatim
	// (mod-indexed into the free-function list); the grammar allows
	// invalid-on-purpose combinations so the frontend analyser is forced
	// to traverse them.
	if (!isLibrary)
	{
		for (int i = 0; i < _c.using_for_size(); i++)
			o << emitUsingFor(_c.using_for(i), /*fileLevel*/ false);
	}

	// State variables (skip for libraries)
	if (!isLibrary)
	{
		// Counter for generating unique literal values for constant/immutable vars
		unsigned initLiteralIdx = 0;
		for (auto const& sv : info.stateVars)
		{
			o << "\t" << sv.typeStr;
			if (sv.isTransient)
				o << " transient";
			else if (sv.isConstant)
				o << " constant";
			else if (sv.isImmutable)
				o << " immutable";
			o << " public " << sv.name;
			// Constants need a compile-time initializer
			if (sv.isConstant)
				o << " = " << sv.typeStr << "(" << (initLiteralIdx * 7 + 3) << ")";
			if (sv.isConstant || sv.isImmutable)
				initLiteralIdx++;
			o << ";\n";
		}
		if (!info.stateVars.empty())
			o << "\n";
	}

	// Events
	for (auto const& ev : info.events)
	{
		o << "\tevent " << ev.name << "(";
		for (unsigned j = 0; j < ev.numParams; j++)
		{
			if (j > 0) o << ", ";
			o << "uint256";
			if (j < ev.indexedParams.size() && ev.indexedParams[j])
				o << " indexed";
		}
		o << ");\n";
	}

	// Errors
	for (auto const& err : info.errors)
	{
		o << "\terror " << err.name << "(";
		for (unsigned j = 0; j < err.numParams; j++)
		{
			if (j > 0) o << ", ";
			o << "uint256 " << err.paramNames[j];
		}
		o << ");\n";
	}

	if (!info.events.empty() || !info.errors.empty())
		o << "\n";

	// Modifiers
	for (unsigned j = 0; j < info.modifiers.size(); j++)
	{
		o << "\tmodifier " << info.modifiers[j].name << "() {\n";
		m_inModifier = true;
		o << setupAndVisitBlock(_c.modifiers(j).body(), info, NONPAYABLE, 2);
		m_inModifier = false;
		o << "\t\t_;\n";
		o << "\t}\n\n";
	}

	// Check if we have immutable vars that need constructor assignment
	bool hasImmutables = false;
	for (auto const& sv : info.stateVars)
		if (sv.isImmutable)
		{
			hasImmutables = true;
			break;
		}

	// Constructor — generate one if we have a proto constructor or immutable vars
	if (!isLibrary && (_c.has_constructor() || hasImmutables))
	{
		bool payable = _c.has_constructor() && _c.constructor().payable();
		bool hasParam = info.hasCtorParam;
		o << "\tconstructor(";
		if (hasParam)
			o << "uint256 _cp";
		o << ") ";
		if (payable)
			o << "payable ";
		o << "{\n";
		// Store constructor param in first state var if available
		if (hasParam && !info.stateVars.empty())
		{
			auto const& sv = info.stateVars[0];
			if (!sv.isConstant && !sv.isImmutable)
				o << "\t\t" << sv.name << " = " << sv.typeStr << "(_cp);\n";
		}

		// Set up state for constructor body
		m_canReadState = true;
		m_inConstructor = true;
		m_canReturn = false;
		m_currentReturnsTwo = false;
		m_currentStructReturnType.clear();
		m_currentStructReturnFieldCount = 0;
		m_currentMutability = payable ? PAYABLE : NONPAYABLE;
		m_currentFuncIdx = 0;
		collectInheritedInfo(info);

		// Assign immutable state vars before the body so the body can read them
		{
			unsigned immIdx = 0;
			for (auto const& sv : info.stateVars)
				if (sv.isImmutable)
					o << "\t\t" << sv.name << " = " << sv.typeStr
					  << "(" << (immIdx++ * 7 + 3) << ");\n";
		}

		pushScope();
		m_localVarCount = 0;
		m_varCounter = 0;
		m_indentLevel = 2;
		m_stmtDepth = 0;
		if (_c.has_constructor())
			o << visitBlock(_c.constructor().body());
		popScope();

		m_inConstructor = false;

		o << "\t}\n\n";
	}

	// Check how many base contracts define receive/fallback (for override keyword)
	unsigned basesWithReceive = 0;
	unsigned basesWithFallback = 0;
	for (unsigned baseIdx : info.baseIndices)
	{
		if (m_contracts[baseIdx].hasReceive)
			basesWithReceive++;
		if (m_contracts[baseIdx].hasFallback)
			basesWithFallback++;
	}

	// Receive function — must also generate override if multiple bases define receive
	bool emitReceive = !isLibrary && (_c.has_receive() || basesWithReceive >= 2);
	if (emitReceive)
	{
		o << "\treceive() external payable virtual";
		if (basesWithReceive > 0)
			o << " override";
		o << " {\n";
		m_inReceive = true;
		if (_c.has_receive())
			o << setupAndVisitBlock(_c.receive().body(), info, PAYABLE, 2);
		m_inReceive = false;
		o << "\t}\n\n";
		m_contracts[_idx].hasReceive = true;
	}

	// Fallback function — must also generate override if multiple bases define fallback
	bool emitFallback = !isLibrary && (_c.has_fallback_func() || basesWithFallback >= 2);
	if (emitFallback)
	{
		o << "\tfallback() external payable virtual";
		if (basesWithFallback > 0)
			o << " override";
		o << " {\n";
		if (_c.has_fallback_func())
			o << setupAndVisitBlock(_c.fallback_func().body(), info, PAYABLE, 2);
		o << "\t}\n\n";
		m_contracts[_idx].hasFallback = true;
	}

	// Functions
	unsigned numProtoFuncs = std::min(
		static_cast<unsigned>(_c.functions_size()),
		s_maxFunctions
	);
	for (unsigned j = 0; j < info.functions.size(); j++)
	{
		if (j < numProtoFuncs)
			o << visitFunction(_c.functions(j), info, j) << "\n";
		else
		{
			// Injected function with no proto body — generate a stub
			auto const& fi = info.functions[j];
			o << "\tfunction " << fi.name << "(";
			for (unsigned p = 0; p < fi.numParams; p++)
			{
				if (p > 0) o << ", ";
				ParamType pt = (p < fi.paramTypes.size()) ? fi.paramTypes[p] : PARAM_UINT256;
				if (pt == PARAM_UINT256)
					o << "uint256 p" << p;
				else if (pt == PARAM_STRUCT)
					o << fi.structParamTypeName << " memory _p" << p;
				else
					o << paramTypeSolStr(pt) << " _p" << p;
			}
			o << ") public";
			if (fi.mut == PURE) o << " pure";
			else if (fi.mut == VIEW) o << " view";
			if (!isLibrary && fi.vis != PRIVATE && !fi.nonVirtual)
				o << " virtual";
			if (!isLibrary && fi.isOverride)
				o << " override";
			if (fi.returnsStruct)
			{
				o << " returns (" << fi.structParamTypeName << " memory) {\n";
				o << "\t\treturn " << fi.structParamTypeName << "(" << defaultUintLiteral();
				for (unsigned k = 1; k < fi.structParamFieldCount; k++)
					o << ", 0";
				o << ");\n";
			}
			else if (fi.returnTwo)
			{
				o << " returns (uint256, uint256) {\n";
				o << "\t\treturn (" << defaultUintLiteral() << ", " << defaultUintLiteral() << ");\n";
			}
			else
			{
				o << " returns (uint256) {\n";
				o << "\t\treturn " << defaultUintLiteral() << ";\n";
			}
			o << "\t}\n\n";
		}
	}

	// Only emit calldataload/calldatasize helpers if actually used by
	// expressions in this contract. Skipping them reduces code size and
	// compilation time for the common case where they're not needed.
	if (m_usedCdl)
	{
		o << "\tfunction _cdl" << _idx << "(uint256 _o) private pure returns (uint256 _v) {\n";
		o << "\t\tassembly { _v := calldataload(_o) }\n";
		o << "\t}\n";
	}
	if (m_usedCds)
	{
		o << "\tfunction _cds" << _idx << "() private pure returns (uint256 _s) {\n";
		o << "\t\tassembly { _s := calldatasize() }\n";
		o << "\t}\n";
	}

	o << "}\n";
	return o.str();
}

// =====================================================================
// Function generation
// =====================================================================

std::string ProtoConverter::visitFunction(
	FunctionDef const& _f,
	ContractInfo const& _cinfo,
	unsigned _funcIdx
)
{
	auto const& fi = _cinfo.functions[_funcIdx];
	m_currentFuncIdx = _funcIdx;
	bool isLibrary = (_cinfo.kind == ContractDef::LIBRARY);

	// Determine visibility
	std::string vis;
	if (isLibrary)
		vis = "internal";
	else
	{
		switch (fi.vis)
		{
		case PUBLIC: vis = "public"; break;
		case EXTERNAL: vis = "external"; break;
		case INTERNAL: vis = "internal"; break;
		case PRIVATE: vis = "private"; break;
		}
	}

	// Determine mutability
	std::string mut;
	StateMutability actualMut = fi.mut;
	// Libraries can't be payable
	if (isLibrary && actualMut == PAYABLE)
		actualMut = PURE;
	// Internal/private functions cannot be payable in Solidity
	if ((vis == "internal" || vis == "private") && actualMut == PAYABLE)
		actualMut = NONPAYABLE;
	// External/public functions that are payable need special care
	switch (actualMut)
	{
	case PURE: mut = "pure"; break;
	case VIEW: mut = "view"; break;
	case PAYABLE: mut = "payable"; break;
	case NONPAYABLE: mut = ""; break;
	}

	// Track current mutability for expression generation
	m_currentMutability = actualMut;
	m_canReturn = true;
	m_currentReturnsTwo = fi.returnTwo;
	m_currentStructReturnType = fi.returnsStruct ? fi.structParamTypeName : "";
	m_currentStructReturnFieldCount = fi.returnsStruct ? fi.structParamFieldCount : 0;

	// Set up state access
	m_canReadState = (actualMut == VIEW || actualMut == NONPAYABLE || actualMut == PAYABLE);
	collectInheritedInfo(_cinfo);

	// Push scope and add params (as uint256 shadow vars)
	pushScope();
	m_localVarCount = 0;
	m_varCounter = 0;
	for (unsigned i = 0; i < fi.numParams; i++)
		addVar("p" + std::to_string(i));

	// Generate body (indented inside function {})
	m_indentLevel = 2;
	m_stmtDepth = 0;
	std::string body = visitBlock(_f.body());

	popScope();

	// Build function string
	std::ostringstream o;
	o << "\tfunction " << fi.name << "(";
	for (unsigned i = 0; i < fi.numParams; i++)
	{
		if (i > 0) o << ", ";
		ParamType pt = (i < fi.paramTypes.size()) ? fi.paramTypes[i] : PARAM_UINT256;
		if (pt == PARAM_UINT256)
			o << "uint256 p" << i;
		else if (pt == PARAM_STRUCT)
			o << fi.structParamTypeName << " memory _p" << i;
		else
			o << paramTypeSolStr(pt) << " _p" << i;
	}
	o << ") " << vis;
	if (!mut.empty())
		o << " " << mut;

	// virtual / override markers. Non-library, non-private functions are
	// `virtual` by default (so a derived contract can override them);
	// `non_virtual` suppresses that. `override` is emitted when this
	// function was bound to a base function during the inheritance pass.
	if (!isLibrary && fi.vis != PRIVATE && !fi.nonVirtual)
		o << " virtual";
	if (!isLibrary && fi.isOverride)
		o << " override";

	// Apply modifier if specified — only for nonpayable/payable functions.
	// Modifier bodies are generated with NONPAYABLE mutability, so applying
	// them to pure (state reads) or view (emit) functions causes compile errors.
	if (_f.has_modifier_id() && !_cinfo.modifiers.empty() &&
		actualMut != PURE && actualMut != VIEW)
	{
		unsigned modIdx = _f.modifier_id() % _cinfo.modifiers.size();
		o << " " << _cinfo.modifiers[modIdx].name << "()";
	}

	if (fi.returnsStruct)
		o << " returns (" << fi.structParamTypeName << " memory) {\n";
	else if (fi.returnTwo)
		o << " returns (uint256, uint256) {\n";
	else
		o << " returns (uint256) {\n";
	// Convert non-uint256 parameters to uint256 shadow variables so the
	// rest of the body can uniformly use uint256 expressions.
	for (unsigned i = 0; i < fi.numParams; i++)
	{
		ParamType pt = (i < fi.paramTypes.size()) ? fi.paramTypes[i] : PARAM_UINT256;
		if (pt == PARAM_BOOL)
			o << "\t\tuint256 p" << i << " = _p" << i << " ? 1 : 0;\n";
		else if (pt == PARAM_ADDRESS)
			o << "\t\tuint256 p" << i << " = uint256(uint160(_p" << i << "));\n";
		else if (pt == PARAM_BYTES32)
			o << "\t\tuint256 p" << i << " = uint256(_p" << i << ");\n";
		else if (pt == PARAM_STRUCT)
			o << "\t\tuint256 p" << i << " = _p" << i << ".f0;\n";
	}
	o << body;
	// Always return something to ensure the function compiles
	if (fi.returnsStruct)
	{
		o << "\t\treturn " << fi.structParamTypeName << "(0";
		for (unsigned k = 1; k < fi.structParamFieldCount; k++)
			o << ", 0";
		o << ");\n";
	}
	else if (fi.returnTwo)
		o << "\t\treturn (0, 0);\n";
	else
		o << "\t\treturn 0;\n";
	o << "\t}\n";

	return o.str();
}

// =====================================================================
// Block and statement generation
// =====================================================================

std::string ProtoConverter::visitBlock(Block const& _b)
{
	pushScope();
	// Save local var count so variables declared in this block don't
	// permanently consume the budget after the block exits.
	unsigned savedLocalVarCount = m_localVarCount;
	std::ostringstream o;

	unsigned numStmts = std::min(
		static_cast<unsigned>(_b.stmts_size()),
		s_maxStmtsPerBlock
	);
	for (unsigned i = 0; i < numStmts; i++)
		o << visitStatement(_b.stmts(i));

	popScope();
	m_localVarCount = savedLocalVarCount;
	return o.str();
}

std::string ProtoConverter::visitStatement(Statement const& _s)
{
	if (m_stmtDepth >= s_maxStmtDepth)
		return "";

	m_stmtDepth++;
	std::string result;

	switch (_s.stmt_oneof_case())
	{
	case Statement::kVarDecl:
		result = visitVarDecl(_s.var_decl());
		break;
	case Statement::kExprStmt:
		result = visitExprStmt(_s.expr_stmt());
		break;
	case Statement::kIfStmt:
		result = visitIf(_s.if_stmt());
		break;
	case Statement::kForStmt:
		result = visitFor(_s.for_stmt());
		break;
	case Statement::kWhileStmt:
		result = visitWhile(_s.while_stmt());
		break;
	case Statement::kDoWhile:
		result = visitDoWhile(_s.do_while());
		break;
	case Statement::kReturnStmt:
		// return <value> is only valid in regular functions (not in
		// modifiers, constructors, receive, or fallback)
		if (m_canReturn)
			result = visitReturn(_s.return_stmt());
		break;
	case Statement::kEmitStmt:
		// Events are side effects: skip in pure and view functions
		if (m_currentMutability != PURE && m_currentMutability != VIEW)
			result = visitEmit(_s.emit_stmt());
		break;
	case Statement::kRevertStmt:
		// Skip revert in constructors (would fail contract creation)
		if (!m_inConstructor)
			result = visitRevert(_s.revert_stmt());
		break;
	case Statement::kBlock:
	{
		std::ostringstream o;
		o << indent() << "{\n";
		m_indentLevel++;
		o << visitBlock(_s.block());
		m_indentLevel--;
		o << indent() << "}\n";
		result = o.str();
		break;
	}
	case Statement::kUnchecked:
	{
		// Solidity forbids nested unchecked blocks. If we're already inside
		// one, generate a plain block instead.
		if (m_inUnchecked)
		{
			std::ostringstream uo;
			uo << indent() << "{\n";
			m_indentLevel++;
			uo << visitBlock(_s.unchecked().body());
			m_indentLevel--;
			uo << indent() << "}\n";
			result = uo.str();
		}
		else
		{
			m_inUnchecked = true;
			result = visitUnchecked(_s.unchecked());
			m_inUnchecked = false;
		}
		break;
	}
	case Statement::kBreakStmt:
		if (m_inLoop)
			result = indent() + "break;\n";
		break;
	case Statement::kContinueStmt:
		if (m_inLoop)
			result = indent() + "continue;\n";
		break;
	case Statement::kRequireStmt:
		result = visitRequire(_s.require_stmt());
		break;
	case Statement::kDeleteStmt:
		result = visitDelete(_s.delete_stmt());
		break;
	case Statement::kTryCatch:
		result = visitTryCatch(_s.try_catch());
		break;
	case Statement::kIndexAssign:
		// Array/mapping writes require non-pure, non-view context
		if (m_currentMutability != PURE && m_currentMutability != VIEW)
			result = visitIndexAssign(_s.index_assign());
		break;
	case Statement::kTupleAssign:
		result = visitTupleAssign(_s.tuple_assign());
		break;
	case Statement::kArrayPush:
		// Array push requires non-pure, non-view context (state modification)
		if (m_currentMutability != PURE && m_currentMutability != VIEW)
			result = visitArrayPush(_s.array_push());
		break;
	case Statement::kArrayPop:
		// Array pop requires non-pure, non-view context (state modification)
		if (m_currentMutability != PURE && m_currentMutability != VIEW)
			result = visitArrayPop(_s.array_pop());
		break;
	case Statement::kTupleDestruct:
		result = visitTupleDestruct(_s.tuple_destruct());
		break;
	case Statement::kStructLocalDecl:
		result = visitStructLocalDecl(_s.struct_local_decl());
		break;
	case Statement::kStructTupleAlias:
		result = visitStructTupleAlias(_s.struct_tuple_alias());
		break;
	case Statement::kSelfdestructStmt:
		// selfdestruct requires non-pure, non-view. Skip in constructors
		// (would destroy the contract being created).
		if (m_currentMutability != PURE && m_currentMutability != VIEW && !m_inConstructor)
		{
			std::string addr = visitUintExpr(_s.selfdestruct_stmt().beneficiary());
			result = indent() + "selfdestruct(payable(address(uint160(uint256(" + addr + ")))));\n";
		}
		break;
	case Statement::kBareMagic:
	{
		// Emit a bare magic-member reference as a standalone expression
		// statement — Solidity parses this but codegen ICEs on
		// "Unknown magic member" (#16612). Accept that most such
		// statements won't reach codegen (earlier rejection is fine).
		std::string member;
		switch (_s.bare_magic().kind())
		{
		case BareMagicStmt::ABI_ENCODE_CALL:        member = "abi.encodeCall"; break;
		case BareMagicStmt::ABI_ENCODE:             member = "abi.encode"; break;
		case BareMagicStmt::ABI_ENCODE_PACKED:      member = "abi.encodePacked"; break;
		case BareMagicStmt::ABI_DECODE:             member = "abi.decode"; break;
		case BareMagicStmt::ABI_ENCODE_WITH_SELECTOR:  member = "abi.encodeWithSelector"; break;
		case BareMagicStmt::ABI_ENCODE_WITH_SIGNATURE: member = "abi.encodeWithSignature"; break;
		}
		if (!member.empty())
			result = indent() + member + ";\n";
		break;
	}
	case Statement::kFixedAsm:
	{
		// `fixed`/`ufixed` local assigned from inline assembly — TypeChecker
		// has no handler for FixedPointType in the assembly visitor and ICEs
		// with "FixedPointType not implemented" (#16619). The shape is
		// hermetic: a block-scoped local + a one-line assembly block.
		std::string tname =
			_s.fixed_asm().kind() == FixedAsmStmt::UFIXED_LOCAL ? "ufixed" : "fixed";
		std::ostringstream o;
		o << indent() << "{\n";
		m_indentLevel++;
		o << indent() << tname << " _fx;\n";
		o << indent() << "assembly { _fx := 1 }\n";
		m_indentLevel--;
		o << indent() << "}\n";
		result = o.str();
		break;
	}
	case Statement::kAbiEncodeStruct:
	{
		// `S memory _es; abi.encode(_es);` — encoding a memory struct whose
		// (inherited) array field is oversized ICEs
		// `ArrayType::calldataEncodedSize` (#16621). Memory types bypass the
		// size check that calldata enforces.
		if (!m_currentStructDefs.empty())
		{
			unsigned sidx = _s.abi_encode_struct().struct_idx()
				% m_currentStructDefs.size();
			std::string const& sname = m_currentStructDefs[sidx].name;
			bool wrap = _s.abi_encode_struct().has_wrap_in_array()
				&& _s.abi_encode_struct().wrap_in_array();
			std::ostringstream o;
			o << indent() << "{\n";
			m_indentLevel++;
			if (wrap)
				o << indent() << sname << "[1] memory _es;\n";
			else
				o << indent() << sname << " memory _es;\n";
			o << indent() << "abi.encode(_es);\n";
			m_indentLevel--;
			o << indent() << "}\n";
			result = o.str();
		}
		break;
	}
	case Statement::kFuncPtr:
	{
		// Internal function pointer: declare a local of matching
		// signature, bind it to a same-contract function, invoke it.
		// Exercises type-of, assignment, and invocation codepaths for
		// FunctionType (internal, bound). Skipped if no eligible target.
		if (m_currentContract >= m_contracts.size())
			break;
		auto const& cinfo = m_contracts[m_currentContract];
		struct FpRef { unsigned idx; };
		std::vector<FpRef> eligible;
		for (unsigned fi = 0; fi < cinfo.functions.size(); fi++)
		{
			auto const& t = cinfo.functions[fi];
			if (t.vis == EXTERNAL) continue;
			if (t.returnTwo || t.returnsStruct) continue;
			if (t.numParams == 0 || t.numParams > 3) continue;
			bool allUint = true;
			for (auto pt : t.paramTypes)
				if (pt != PARAM_UINT256) { allUint = false; break; }
			if (!allUint) continue;
			// Mutability compatibility with the current function.
			if (m_currentMutability == PURE && t.mut != PURE) continue;
			if (m_currentMutability == VIEW && t.mut != PURE && t.mut != VIEW)
				continue;
			eligible.push_back({fi});
		}
		if (eligible.empty())
			break;

		auto const& fp = _s.func_ptr();
		auto const& target = cinfo.functions[
			eligible[fp.target_id() % eligible.size()].idx];

		std::string mutStr;
		switch (target.mut)
		{
		case PURE: mutStr = "pure"; break;
		case VIEW: mutStr = "view"; break;
		case PAYABLE:
		case NONPAYABLE:
			mutStr = "";
			break;
		}

		std::string sigParams;
		for (unsigned i = 0; i < target.numParams; i++)
			sigParams += (i == 0 ? "uint256" : ",uint256");

		unsigned fpIdx = m_localVarCount++;
		std::string ptrName = "fp_" + std::to_string(fpIdx);
		std::string valName = "fpv_" + std::to_string(fpIdx);

		std::ostringstream o;
		o << indent() << "function(" << sigParams << ") internal";
		if (!mutStr.empty())
			o << " " << mutStr;
		o << " returns (uint256) " << ptrName << " = " << target.name << ";\n";
		o << indent() << "uint256 " << valName << " = " << ptrName << "(";
		for (unsigned i = 0; i < target.numParams; i++)
		{
			if (i > 0) o << ", ";
			if (i < static_cast<unsigned>(fp.args_size()))
				o << visitUintExpr(fp.args(i));
			else
				o << "0";
		}
		o << ");\n";
		addVar(valName);
		result = o.str();
		break;
	}
	default:
		break;
	}

	m_stmtDepth--;
	return result;
}

std::string ProtoConverter::visitVarDecl(VarDeclStmt const& _s)
{
	if (m_localVarCount >= s_maxLocalVars)
		return "";

	std::string varName = "v" + std::to_string(m_varCounter++);
	m_localVarCount++;

	std::ostringstream o;
	o << indent() << "uint256 " << varName;
	if (_s.has_init())
		o << " = " << visitUintExpr(_s.init());
	else
		o << " = 0";
	o << ";\n";

	// Add variable to scope AFTER generating the initializer to prevent
	// self-referential expressions like `uint256 v0 = f(v0)`.
	addVar(varName);

	return o.str();
}

std::string ProtoConverter::visitExprStmt(ExprStmt const& _s)
{
	// Generate a uint expression as a statement (useful for assignments, function calls)
	std::string expr = visitUintExpr(_s.expr());
	if (expr.empty())
		return "";
	return indent() + expr + ";\n";
}

std::string ProtoConverter::visitIf(IfStmt const& _s)
{
	std::ostringstream o;
	o << indent() << "if (" << visitBoolExpr(_s.cond()) << ") {\n";
	m_indentLevel++;
	o << visitBlock(_s.if_body());
	m_indentLevel--;
	if (_s.has_else_body())
	{
		o << indent() << "} else {\n";
		m_indentLevel++;
		o << visitBlock(_s.else_body());
		m_indentLevel--;
	}
	o << indent() << "}\n";
	return o.str();
}

std::string ProtoConverter::visitFor(ForStmt const& _s)
{
	// Skip if we'd exceed local variable limit (iter var needs a slot)
	if (m_localVarCount >= s_maxLocalVars)
		return "";

	// Always generate a bounded for loop to prevent infinite loops
	std::string iterVar = "i" + std::to_string(m_varCounter++);
	unsigned bound = s_maxForIter;

	std::ostringstream o;
	o << indent() << "for (uint256 " << iterVar << " = 0; "
	  << iterVar << " < " << bound << "; "
	  << iterVar << "++) {\n";

	pushScope();
	addVar(iterVar);
	m_localVarCount++;

	bool wasInLoop = m_inLoop;
	m_inLoop = true;
	m_indentLevel++;
	o << visitBlock(_s.body());
	m_indentLevel--;
	m_inLoop = wasInLoop;

	popScope();
	o << indent() << "}\n";
	return o.str();
}

std::string ProtoConverter::visitWhile(WhileStmt const& _s)
{
	// Skip if we'd exceed local variable limit (counter var needs a slot)
	if (m_localVarCount >= s_maxLocalVars)
		return "";

	// Bounded while loop with a counter
	std::string counterVar = "w" + std::to_string(m_varCounter++);
	unsigned bound = s_maxForIter;

	std::ostringstream o;
	o << indent() << "{\n";
	m_indentLevel++;
	o << indent() << "uint256 " << counterVar << " = 0;\n";

	pushScope();
	addVar(counterVar);
	m_localVarCount++;

	o << indent() << "while (" << visitBoolExpr(_s.cond())
	  << " && " << counterVar << " < " << bound << ") {\n";

	bool wasInLoop = m_inLoop;
	m_inLoop = true;
	m_indentLevel++;
	o << indent() << counterVar << "++;\n";
	o << visitBlock(_s.body());
	m_indentLevel--;
	m_inLoop = wasInLoop;

	o << indent() << "}\n";
	popScope();
	m_indentLevel--;
	o << indent() << "}\n";
	return o.str();
}

std::string ProtoConverter::visitDoWhile(DoWhileStmt const& _s)
{
	// Skip if we'd exceed local variable limit (counter var needs a slot)
	if (m_localVarCount >= s_maxLocalVars)
		return "";

	// Bounded do-while
	std::string counterVar = "d" + std::to_string(m_varCounter++);
	unsigned bound = s_maxForIter;

	std::ostringstream o;
	o << indent() << "{\n";
	m_indentLevel++;
	o << indent() << "uint256 " << counterVar << " = 0;\n";

	pushScope();
	addVar(counterVar);
	m_localVarCount++;

	o << indent() << "do {\n";

	bool wasInLoop = m_inLoop;
	m_inLoop = true;
	m_indentLevel++;
	o << indent() << counterVar << "++;\n";
	o << visitBlock(_s.body());
	m_indentLevel--;
	m_inLoop = wasInLoop;

	o << indent() << "} while (" << visitBoolExpr(_s.cond())
	  << " && " << counterVar << " < " << bound << ");\n";
	popScope();
	m_indentLevel--;
	o << indent() << "}\n";
	return o.str();
}

std::string ProtoConverter::visitReturn(ReturnStmt const& _s)
{
	std::ostringstream o;
	if (!m_currentStructReturnType.empty())
	{
		std::string v = _s.has_val() ? visitUintExpr(_s.val()) : "0";
		o << indent() << "return " << m_currentStructReturnType << "(" << v;
		for (unsigned k = 1; k < m_currentStructReturnFieldCount; k++)
			o << ", 0";
		o << ");\n";
	}
	else if (m_currentReturnsTwo)
	{
		std::string v1 = _s.has_val() ? visitUintExpr(_s.val()) : "0";
		std::string v2 = std::to_string(randomNumber() % 100);
		o << indent() << "return (" << v1 << ", " << v2 << ");\n";
	}
	else if (_s.has_val())
		o << indent() << "return " << visitUintExpr(_s.val()) << ";\n";
	else
		o << indent() << "return 0;\n";
	return o.str();
}

std::string ProtoConverter::visitEmit(EmitStmt const& _s)
{
	if (m_currentEvents.empty())
		return "";

	unsigned evIdx = _s.event_id() % m_currentEvents.size();
	auto const& ev = m_currentEvents[evIdx];

	std::ostringstream o;
	o << indent() << "emit " << ev.name << "(";
	for (unsigned i = 0; i < ev.numParams; i++)
	{
		if (i > 0) o << ", ";
		if (i < static_cast<unsigned>(_s.args_size()))
			o << visitUintExpr(_s.args(i));
		else
			o << "0";
	}
	o << ");\n";
	return o.str();
}

std::string ProtoConverter::visitRevert(RevertStmt const& _s)
{
	if (m_currentErrors.empty())
		return "";

	unsigned errIdx = _s.error_id() % m_currentErrors.size();
	auto const& err = m_currentErrors[errIdx];
	bool useNamed = _s.has_use_named_args() && _s.use_named_args();

	std::ostringstream o;
	if (useNamed)
	{
		// Named parameter syntax: revert Err({param1: val1, param2: val2})
		o << indent() << "revert " << err.name << "({";
		for (unsigned i = 0; i < err.numParams; i++)
		{
			if (i > 0) o << ", ";
			o << err.paramNames[i] << ": ";
			if (i < static_cast<unsigned>(_s.args_size()))
				o << visitUintExpr(_s.args(i));
			else
				o << "0";
		}
		o << "});\n";
	}
	else
	{
		o << indent() << "revert " << err.name << "(";
		for (unsigned i = 0; i < err.numParams; i++)
		{
			if (i > 0) o << ", ";
			if (i < static_cast<unsigned>(_s.args_size()))
				o << visitUintExpr(_s.args(i));
			else
				o << "0";
		}
		o << ");\n";
	}
	return o.str();
}

std::string ProtoConverter::visitRequire(RequireStmt const& _s)
{
	// Skip require/assert in constructors to avoid reverting during
	// contract creation (test contract uses `new` which propagates reverts)
	if (m_inConstructor)
		return "";

	std::string cond = visitBoolExpr(_s.cond());
	if (_s.is_assert())
		return indent() + "assert(" + cond + ");\n";
	else if (_s.has_error_id() && !m_currentErrors.empty())
	{
		unsigned errIdx = _s.error_id() % m_currentErrors.size();
		auto const& err = m_currentErrors[errIdx];
		bool useNamed = _s.has_use_named_args() && _s.use_named_args();
		std::ostringstream o;
		if (useNamed)
		{
			// require(cond, CustomError({param1: val1, ...}))
			o << indent() << "require(" << cond << ", " << err.name << "({";
			for (unsigned i = 0; i < err.numParams; i++)
			{
				if (i > 0) o << ", ";
				o << err.paramNames[i] << ": 0";
			}
			o << "}));\n";
		}
		else
		{
			// require(cond, CustomError(args))
			o << indent() << "require(" << cond << ", " << err.name << "(";
			for (unsigned i = 0; i < err.numParams; i++)
			{
				if (i > 0) o << ", ";
				o << "0";
			}
			o << "));\n";
		}
		return o.str();
	}
	else if (_s.has_with_message() && _s.with_message())
		return indent() + "require(" + cond + ", \"req_" + std::to_string(randomNumber() % 100) + "\");\n";
	else
		return indent() + "require(" + cond + ");\n";
}

std::string ProtoConverter::visitUnchecked(UncheckedBlock const& _s)
{
	std::ostringstream o;
	o << indent() << "unchecked {\n";
	m_indentLevel++;
	o << visitBlock(_s.body());
	m_indentLevel--;
	o << indent() << "}\n";
	return o.str();
}

std::string ProtoConverter::visitDelete(DeleteStmt const& _s)
{
	// Use findLVar to only delete local variables — deleting state vars
	// would be invalid in view/pure functions.
	std::string var = findLVar(_s.target().index());
	if (var.empty())
		return "";
	return indent() + "delete " + var + ";\n";
}

std::string ProtoConverter::visitTryCatch(TryCatchStmt const& _s)
{
	// try/catch requires non-pure, non-view context (external call)
	if (m_currentMutability == PURE || m_currentMutability == VIEW)
		return "";

	// Find an external function in the current contract to call via this.
	auto const& cinfo = m_contracts[m_currentContract];
	std::vector<unsigned> externalFuncs;
	for (unsigned i = 0; i < cinfo.functions.size(); i++)
	{
		if (cinfo.functions[i].vis == EXTERNAL && i != m_currentFuncIdx)
			externalFuncs.push_back(i);
	}
	if (externalFuncs.empty())
		return "";

	unsigned targetIdx = _s.func_id() % externalFuncs.size();
	auto const& target = cinfo.functions[externalFuncs[targetIdx]];

	std::ostringstream o;
	o << indent() << "try this." << target.name << "(";
	for (unsigned i = 0; i < target.numParams; i++)
	{
		if (i > 0) o << ", ";
		if (i < static_cast<unsigned>(_s.args_size()))
			o << visitUintExpr(_s.args(i));
		else
			o << "0";
	}
	o << ") returns (uint256 _tr) {\n";
	m_indentLevel++;
	o << visitBlock(_s.try_body());
	m_indentLevel--;
	o << indent() << "} catch {\n";
	m_indentLevel++;
	o << visitBlock(_s.catch_body());
	m_indentLevel--;
	o << indent() << "}\n";
	return o.str();
}

std::string ProtoConverter::visitIndexAssign(IndexAssignStmt const& _s)
{
	// Write to a fixed-size array or mapping state variable
	if (m_currentIndexableVars.empty())
		return "";

	unsigned varIdx = _s.var_idx() % m_currentIndexableVars.size();
	auto const& sv = m_currentIndexableVars[varIdx];
	std::string indexExpr = visitUintExpr(_s.index());
	std::string valueExpr = visitUintExpr(_s.value());

	std::ostringstream o;
	if (sv.isFixedArray)
	{
		// Bounds-check with modulo
		o << indent() << sv.name << "[" << indexExpr << " % "
		  << sv.arrayLength << "] = ";
		if (!sv.elementIsUint)
			o << "uint256(" << valueExpr << ")";
		else
			o << valueExpr;
		o << ";\n";
	}
	else if (sv.isMapping)
	{
		std::string key = indexExpr;
		if (sv.mappingKeyTypeStr != "uint256")
			key = sv.mappingKeyTypeStr + "(" + key + ")";
		o << indent() << sv.name << "[" << key << "] = " << valueExpr << ";\n";
	}
	return o.str();
}

std::string ProtoConverter::visitTupleAssign(TupleAssignStmt const& _s)
{
	// Tuple assignment: (a, b) = (expr1, expr2)
	// Need at least 2 local variables
	std::vector<std::string> vars;
	for (auto const& scope : m_scopeStack)
		for (auto const& v : scope)
			vars.push_back(v);
	if (vars.size() < 2)
		return "";

	// Pick two different variables
	unsigned idx1 = 0;
	unsigned idx2 = vars.size() > 1 ? 1 : 0;

	std::string e1 = visitUintExpr(_s.val1());
	std::string e2 = visitUintExpr(_s.val2());
	return indent() + "(" + vars[idx1] + ", " + vars[idx2] + ") = ("
		+ e1 + ", " + e2 + ");\n";
}

std::string ProtoConverter::visitArrayPush(ArrayPushStmt const& _s)
{
	if (m_currentDynArrayVars.empty())
		return "";

	unsigned varIdx = _s.var_idx() % m_currentDynArrayVars.size();
	auto const& sv = m_currentDynArrayVars[varIdx];

	std::ostringstream o;
	if (_s.has_value())
	{
		std::string val = visitUintExpr(_s.value());
		// Cast value to element type if needed
		if (!sv.elementIsUint)
			o << indent() << sv.name << ".push(" << sv.typeStr.substr(0, sv.typeStr.find('['))
			  << "(" << val << "));\n";
		else
			o << indent() << sv.name << ".push(" << val << ");\n";
	}
	else
		o << indent() << sv.name << ".push();\n";
	return o.str();
}

std::string ProtoConverter::visitArrayPop(ArrayPopStmt const& _s)
{
	if (m_currentDynArrayVars.empty())
		return "";

	unsigned varIdx = _s.var_idx() % m_currentDynArrayVars.size();
	auto const& sv = m_currentDynArrayVars[varIdx];

	// Guard against popping from empty array
	std::ostringstream o;
	o << indent() << "if (" << sv.name << ".length > 0) " << sv.name << ".pop();\n";
	return o.str();
}

std::string ProtoConverter::visitStructLocalDecl(StructLocalDeclStmt const& _s)
{
	if (m_localVarCount >= s_maxLocalVars)
		return "";

	auto eligible = eligibleMemoryStructs();
	if (eligible.empty())
		return "";

	unsigned structDefIdx = eligible[_s.struct_idx() % eligible.size()];
	std::string const& sname = m_currentStructDefs[structDefIdx].name;

	std::string varName = "m" + std::to_string(m_varCounter++);
	m_localVarCount++;

	if (!m_structLocalsStack.empty())
		m_structLocalsStack.back().push_back({varName, structDefIdx});

	std::ostringstream o;
	o << indent() << sname << " memory " << varName << ";\n";
	return o.str();
}

std::string ProtoConverter::visitStructTupleAlias(StructTupleAliasStmt const& _s)
{
	// Requires a state-writing context (nonpayable/payable).
	if (m_currentMutability == PURE || m_currentMutability == VIEW)
		return "";
	if (!m_canReadState)
		return "";

	// Candidate resolution strategy:
	//  1. Prefer an already-declared in-scope memory struct local whose
	//     struct type has >= 2 matching storage state vars — that way a
	//     preceding StructLocalDeclStmt can compose with this statement.
	//  2. Otherwise fall back to declaring an anonymous memory local in a
	//     fresh block scope, so a single proto message can trigger the
	//     pattern without requiring libfuzzer to sequence two statements.
	// Either way, the statement is a no-op if no struct type exists with
	// both (a) all-uint-compatible fields and (b) >= 2 storage state vars.
	std::string localName;
	unsigned chosenStructDefIdx = 0;
	std::vector<std::pair<std::string, unsigned>> matchingStateVars;
	bool declareLocalInline = false;

	auto findMatching = [&](unsigned structDefIdx)
	{
		std::vector<std::pair<std::string, unsigned>> match;
		for (auto const& sv : m_currentStructStateVars)
			if (sv.second == structDefIdx)
				match.push_back(sv);
		return match;
	};

	auto locals = allStructLocals();
	if (!locals.empty())
	{
		unsigned nLocals = static_cast<unsigned>(locals.size());
		unsigned startIdx = _s.local_sel() % nLocals;
		for (unsigned probe = 0; probe < nLocals; probe++)
		{
			auto const& cand = locals[(startIdx + probe) % nLocals];
			auto match = findMatching(cand.structDefIdx);
			if (match.size() >= 2)
			{
				localName = cand.name;
				chosenStructDefIdx = cand.structDefIdx;
				matchingStateVars = std::move(match);
				break;
			}
		}
	}

	if (localName.empty())
	{
		auto eligible = eligibleMemoryStructs();
		if (eligible.empty())
			return "";
		unsigned nEligible = static_cast<unsigned>(eligible.size());
		unsigned startIdx = _s.local_sel() % nEligible;
		for (unsigned probe = 0; probe < nEligible; probe++)
		{
			unsigned structDefIdx = eligible[(startIdx + probe) % nEligible];
			auto match = findMatching(structDefIdx);
			if (match.size() >= 2)
			{
				chosenStructDefIdx = structDefIdx;
				matchingStateVars = std::move(match);
				localName = "ma" + std::to_string(m_varCounter++);
				declareLocalInline = true;
				break;
			}
		}
		if (localName.empty())
			return "";
	}

	unsigned nSVs = static_cast<unsigned>(matchingStateVars.size());
	unsigned sa = _s.sa_sel() % nSVs;
	unsigned sb = _s.sb_sel() % nSVs;
	if (sb == sa)
		sb = (sb + 1) % nSVs;
	std::string const& saName = matchingStateVars[sa].first;
	std::string const& sbName = matchingStateVars[sb].first;

	auto const& structDef = m_currentStructDefs[chosenStructDefIdx];
	std::string const& sname = structDef.name;

	// Build two distinct struct literals so the RHS tuple elements carry
	// observably different values — otherwise the legacy/viaIR divergence
	// has nothing to reveal.
	auto makeLiteral = [&](unsigned base)
	{
		std::ostringstream lit;
		lit << sname << "(";
		for (unsigned i = 0; i < structDef.fields.size(); i++)
		{
			if (i > 0) lit << ", ";
			// Small values (< 256) narrow implicitly into any uint width.
			lit << (base + i);
		}
		lit << ")";
		return lit.str();
	};

	std::ostringstream o;
	if (declareLocalInline)
	{
		o << indent() << "{\n";
		m_indentLevel++;
		o << indent() << sname << " memory " << localName << ";\n";
	}
	o << indent() << saName << " = " << makeLiteral(1) << ";\n";
	o << indent() << sbName << " = " << makeLiteral(11) << ";\n";
	o << indent() << "(" << localName << ", " << saName << ") = ("
	  << saName << ", " << sbName << ");\n";
	// Commit the memory struct into storage so the divergence surfaces in
	// the differential storage oracle.
	o << indent() << saName << " = " << localName << ";\n";
	if (declareLocalInline)
	{
		m_indentLevel--;
		o << indent() << "}\n";
	}
	return o.str();
}

std::string ProtoConverter::visitTupleDestruct(TupleDestructStmt const& _s)
{
	// Find a returns_two function with lower index in the current contract
	if (m_currentContract >= m_contracts.size())
		return "";
	auto const& cinfo = m_contracts[m_currentContract];
	unsigned callableCount = std::min(
		m_currentFuncIdx,
		static_cast<unsigned>(cinfo.functions.size())
	);

	// Collect returns_two functions
	std::vector<unsigned> returnsTwoFuncs;
	for (unsigned i = 0; i < callableCount; i++)
	{
		auto const& target = cinfo.functions[i];
		if (!target.returnTwo || target.vis == EXTERNAL)
			continue;
		// Check mutability compatibility
		bool canCall = true;
		if (m_currentMutability == PURE && target.mut != PURE)
			canCall = false;
		if (m_currentMutability == VIEW && target.mut != PURE && target.mut != VIEW)
			canCall = false;
		if (canCall)
			returnsTwoFuncs.push_back(i);
	}

	if (returnsTwoFuncs.empty() || m_localVarCount + 2 > s_maxLocalVars)
		return "";

	unsigned targetIdx = _s.func_id() % returnsTwoFuncs.size();
	auto const& target = cinfo.functions[returnsTwoFuncs[targetIdx]];

	std::string v1 = "v" + std::to_string(m_varCounter++);
	std::string v2 = "v" + std::to_string(m_varCounter++);
	m_localVarCount += 2;

	std::ostringstream o;
	o << indent() << "(uint256 " << v1 << ", uint256 " << v2 << ") = "
	  << target.name << "(";
	for (unsigned i = 0; i < target.numParams; i++)
	{
		if (i > 0) o << ", ";
		if (i < static_cast<unsigned>(_s.args_size()))
			o << visitUintExpr(_s.args(i));
		else
			o << "0";
	}
	o << ");\n";

	addVar(v1);
	addVar(v2);
	return o.str();
}

// =====================================================================
// Expression generation
// =====================================================================

std::string ProtoConverter::visitUintExpr(Expression const& _e)
{
	if (m_exprDepth >= s_maxExprDepth)
		return findVar(0);

	m_exprDepth++;
	std::string result;

	switch (_e.expr_oneof_case())
	{
	case Expression::kLit:
	{
		auto const& lit = _e.lit();
		if (lit.has_int_lit())
		{
			auto const& intLit = lit.int_lit();
			if (intLit.has_ether_unit())
			{
				// Use small values to avoid overflow with ether units
				uint64_t v = intLit.val() % 5;
				switch (intLit.ether_unit())
				{
				case IntegerLiteral::WEI:
					result = std::to_string(intLit.val() % 1000) + " wei";
					break;
				case IntegerLiteral::GWEI:
					result = std::to_string(v) + " gwei";
					break;
				case IntegerLiteral::ETHER:
					result = std::to_string(v) + " ether";
					break;
				}
			}
			else
				result = std::to_string(intLit.val() % 1000);
		}
		else if (lit.has_bool_lit())
			result = lit.bool_lit().val() ? "1" : "0";
		else if (lit.has_addr_lit())
		{
			// Generate a deterministic address as a uint.
			// Include special values: address(0), small addresses, and wider range.
			uint64_t v = lit.addr_lit().val();
			unsigned kind = v % 8;
			if (kind == 0)
				result = "uint256(uint160(0))"; // address(0)
			else if (kind == 1)
				result = "uint256(uint160(1))"; // precompile range
			else if (kind == 2)
				result = "uint256(uint160(0xdead))"; // common test address
			else
				result = "uint256(uint160(" + std::to_string(v) + "))"; // full range
		}
		else if (lit.has_str_lit())
		{
			// Generate a deterministic string literal hashed to uint256.
			// Vary length and content for better coverage: empty, short, long.
			uint32_t seed = lit.str_lit().seed();
			unsigned kind = seed % 4;
			std::string strContent;
			if (kind == 0)
				strContent = ""; // empty string
			else if (kind == 1)
				strContent = "s" + std::to_string(seed % 100); // short
			else if (kind == 2)
				strContent = "str_" + std::to_string(seed) + "_abcdefghijklmnop"; // medium
			else
				strContent = std::string(64, 'x') + std::to_string(seed); // long
			result = "uint256(keccak256(bytes(\"" + strContent + "\")))";
		}
		else
			result = defaultUintLiteral();
		break;
	}
	case Expression::kVarRef:
		result = findVar(_e.var_ref().index());
		break;
	case Expression::kBinOp:
	{
		auto const& op = _e.bin_op();
		if (isArithmeticOp(op.op()))
		{
			// Wrap left in uint256() to force uint256 type and prevent
			// negative int_const folding (e.g. 0 - 42 = int_const -42)
			std::string left = "uint256(" + visitUintExpr(op.left()) + ")";
			std::string right = visitUintExpr(op.right());
			if (op.op() == BinaryOp::DIV || op.op() == BinaryOp::MOD)
			{
				// Make division/modulo safe: use (right | 1) to avoid div-by-zero
				result = left + " " + arithmeticOpStr(op.op()) + " (" + right + " | 1)";
			}
			else if (op.op() == BinaryOp::EXP)
			{
				// Guard exponentiation: clamp exponent to 0-3 to avoid overflow
				result = left + " ** (" + right + " % 4)";
			}
			else
				// When inside an unchecked{} block, arithmetic wraps on overflow
				// instead of reverting. Outside unchecked, overflow will revert.
				result = left + " " + arithmeticOpStr(op.op()) + " " + right;
		}
		else if (isBitwiseOp(op.op()))
		{
			result = visitUintExpr(op.left()) + " " +
				bitwiseOpStr(op.op()) + " " +
				visitUintExpr(op.right());
		}
		else
		{
			// Comparison or logical op used in uint context: wrap in ternary
			// Undo our depth increment to avoid double-counting (visitBoolExpr will increment)
			m_exprDepth--;
			result = "(" + visitBoolExpr(_e) + " ? uint256(1) : uint256(0))";
			m_exprDepth++;
		}
		break;
	}
	case Expression::kUnOp:
	{
		auto const& op = _e.un_op();
		switch (op.op())
		{
		case UnaryOp::BNOT:
			// Wrap operand in uint256() to avoid ~0 producing int_const -1
			result = "~uint256(" + visitUintExpr(op.operand()) + ")";
			break;
		case UnaryOp::NEG:
			// Unary minus is not valid on uint types, use bitwise not instead
			result = "~uint256(" + visitUintExpr(op.operand()) + ")";
			break;
		case UnaryOp::INC_PRE:
		{
			std::string v = findLVar(op.operand().has_var_ref() ? op.operand().var_ref().index() : 0);
			if (v.empty())
				result = defaultUintLiteral();
			else
				result = "++" + v;
			break;
		}
		case UnaryOp::DEC_PRE:
		{
			std::string v = findLVar(op.operand().has_var_ref() ? op.operand().var_ref().index() : 0);
			if (v.empty())
				result = defaultUintLiteral();
			else
				result = "--" + v;
			break;
		}
		case UnaryOp::INC_POST:
		{
			std::string v = findLVar(op.operand().has_var_ref() ? op.operand().var_ref().index() : 0);
			if (v.empty())
				result = defaultUintLiteral();
			else
				result = v + "++";
			break;
		}
		case UnaryOp::DEC_POST:
		{
			std::string v = findLVar(op.operand().has_var_ref() ? op.operand().var_ref().index() : 0);
			if (v.empty())
				result = defaultUintLiteral();
			else
				result = v + "--";
			break;
		}
		default:
			result = defaultUintLiteral();
		}
		break;
	}
	case Expression::kTernary:
		result = "(" + visitBoolExpr(_e.ternary().cond()) + " ? " +
			visitUintExpr(_e.ternary().true_val()) + " : " +
			visitUintExpr(_e.ternary().false_val()) + ")";
		break;
	case Expression::kMsgExpr:
		// msg.sender, msg.value are forbidden in pure functions
		if (m_currentMutability == PURE)
		{
			result = defaultUintLiteral();
			break;
		}
		switch (_e.msg_expr().field())
		{
		case MsgExpr::SENDER:
			result = "uint256(uint160(msg.sender))";
			break;
		case MsgExpr::VALUE:
			// msg.value is only available in payable functions
			if (m_currentMutability == PAYABLE)
				result = "msg.value";
			else
				result = defaultUintLiteral();
			break;
		case MsgExpr::SIG:
			result = "uint256(uint32(msg.sig))";
			break;
		case MsgExpr::DATA:
			// msg.data is forbidden inside receive() functions
			if (m_inReceive)
				result = defaultUintLiteral();
			else
				result = "uint256(keccak256(msg.data))";
			break;
		}
		break;
	case Expression::kBlockExpr:
		// block.* is forbidden in pure functions
		if (m_currentMutability == PURE)
		{
			result = defaultUintLiteral();
			break;
		}
		switch (_e.block_expr().field())
		{
		case BlockExpr::TIMESTAMP:
			result = "block.timestamp";
			break;
		case BlockExpr::NUMBER:
			result = "block.number";
			break;
		case BlockExpr::CHAINID:
			result = "block.chainid";
			break;
		case BlockExpr::BASEFEE:
			result = "block.basefee";
			break;
		case BlockExpr::PREVRANDAO:
			result = "block.prevrandao";
			break;
		case BlockExpr::GASLIMIT:
			result = "block.gaslimit";
			break;
		case BlockExpr::COINBASE:
			result = "uint256(uint160(address(block.coinbase)))";
			break;
		case BlockExpr::BLOBBASEFEE:
			result = "block.blobbasefee";
			break;
		}
		break;
	case Expression::kTxExpr:
		// tx.* is forbidden in pure functions
		if (m_currentMutability == PURE)
		{
			result = defaultUintLiteral();
			break;
		}
		switch (_e.tx_expr().field())
		{
		case TxExpr::ORIGIN:
			result = "uint256(uint160(tx.origin))";
			break;
		case TxExpr::GASPRICE:
			result = "tx.gasprice";
			break;
		}
		break;
	case Expression::kHashExpr:
	{
		// keccak256/sha256/ripemd160 are allowed in pure functions
		auto const& h = _e.hash_expr();
		std::string inner = visitUintExpr(h.arg());
		if (h.kind() == HashExpr::KECCAK256)
			result = "uint256(keccak256(abi.encode(" + inner + ")))";
		else if (h.kind() == HashExpr::SHA256)
			result = "uint256(sha256(abi.encode(" + inner + ")))";
		else
			result = "uint256(uint160(ripemd160(abi.encode(" + inner + "))))";
		break;
	}
	case Expression::kMathExpr:
	{
		auto const& m = _e.math_expr();
		std::string x = visitUintExpr(m.x());
		std::string y = visitUintExpr(m.y());
		std::string mod = "(" + visitUintExpr(m.mod()) + " | 1)";
		if (m.kind() == MathExpr::ADDMOD)
			result = "addmod(" + x + ", " + y + ", " + mod + ")";
		else
			result = "mulmod(" + x + ", " + y + ", " + mod + ")";
		break;
	}
	case Expression::kBuiltin:
	{
		auto const& b = _e.builtin();
		// Calldata builtins are safe in all mutability contexts (including pure)
		// but NOT in free functions (the _cdl/_cds helpers are contract-private)
		if (b.kind() == BuiltinExpr::CALLDATALOAD && !m_inFreeFunction)
		{
			std::string arg = b.has_arg() ? visitUintExpr(b.arg()) : "0";
			result = "_cdl" + std::to_string(m_currentContract) + "(" + arg + ")";
			m_usedCdl = true;
			break;
		}
		if (b.kind() == BuiltinExpr::CALLDATASIZE && !m_inFreeFunction)
		{
			// Use assembly helper so it works in pure functions
			result = "_cds" + std::to_string(m_currentContract) + "()";
			m_usedCds = true;
			break;
		}
		if ((b.kind() == BuiltinExpr::CALLDATALOAD || b.kind() == BuiltinExpr::CALLDATASIZE) && m_inFreeFunction)
		{
			result = defaultUintLiteral();
			break;
		}
		// Other builtins are forbidden in pure functions
		if (m_currentMutability == PURE)
		{
			result = defaultUintLiteral();
			break;
		}
		switch (b.kind())
		{
		case BuiltinExpr::GASLEFT:
			// gasleft() is non-deterministic across optimization levels,
			// so we suppress it for differential testing.
			result = defaultUintLiteral();
			break;
		case BuiltinExpr::BLOCKHASH:
		{
			std::string arg = b.has_arg() ? visitUintExpr(b.arg()) : "0";
			result = "uint256(blockhash(" + arg + "))";
			break;
		}
		case BuiltinExpr::BLOBHASH:
		{
			std::string arg = b.has_arg() ? visitUintExpr(b.arg()) : "0";
			result = "uint256(blobhash(" + arg + "))";
			break;
		}
		case BuiltinExpr::THIS_BALANCE:
			// Avoid address(this).balance — the contract address differs across
			// optimization configs (different bytecode → different CREATE address),
			// causing false positives in differential comparisons.
			result = "uint256(0)";
			break;
		case BuiltinExpr::CALLDATALOAD:
		case BuiltinExpr::CALLDATASIZE:
			break; // handled above
		}
		break;
	}
	case Expression::kAssign:
	{
		auto const& a = _e.assign();
		std::string lhs = findLVar(a.lhs().index());
		if (lhs.empty())
		{
			result = defaultUintLiteral();
			break;
		}
		std::string rhs = visitUintExpr(a.rhs());
		if (a.op() == AssignExpr::DIV_ASSIGN || a.op() == AssignExpr::MOD_ASSIGN)
		{
			// Avoid div-by-zero: do regular assignment with safe division
			if (a.op() == AssignExpr::DIV_ASSIGN)
				result = "(" + lhs + " = " + lhs + " / (" + rhs + " | 1))";
			else
				result = "(" + lhs + " = " + lhs + " % (" + rhs + " | 1))";
		}
		else
			result = "(" + lhs + " " + assignOpStr(a.op()) + " " + rhs + ")";
		break;
	}
	case Expression::kFuncCall:
	{
		auto const& fc = _e.func_call();
		// Guard: skip contract function calls when not inside a contract
		// (e.g., inside a free function body)
		bool inContract = m_currentContract < m_contracts.size();
		unsigned callableCount = 0;
		if (inContract)
		{
			callableCount = std::min(
				m_currentFuncIdx,
				static_cast<unsigned>(m_contracts[m_currentContract].functions.size())
			);
		}
		if (callableCount > 0)
		{
			unsigned targetIdx = fc.func_id() % callableCount;
			auto const& target = m_contracts[m_currentContract].functions[targetIdx];
			// Skip external functions (need this. prefix which changes context)
			// Skip returns_two functions (can't be used as uint256 expressions)
			// Skip functions that return a struct or take struct params —
			// calling them requires struct literals at the call site.
			bool targetUsesStruct = target.returnsStruct;
			for (auto pt : target.paramTypes)
				if (pt == PARAM_STRUCT) { targetUsesStruct = true; break; }
			if (target.vis != EXTERNAL && !target.returnTwo && !targetUsesStruct)
			{
				// Check mutability compatibility:
				// pure can only call pure
				// view can call pure or view
				bool canCall = true;
				if (m_currentMutability == PURE && target.mut != PURE)
					canCall = false;
				if (m_currentMutability == VIEW && target.mut != PURE && target.mut != VIEW)
					canCall = false;

				if (canCall)
				{
					std::ostringstream call;
					// Named argument syntax: func({p0: val, p1: val})
					bool useNamed = fc.has_use_named_args() &&
						fc.use_named_args() && target.numParams > 0;
					if (useNamed)
					{
						call << target.name << "({";
						for (unsigned i = 0; i < target.numParams; i++)
						{
							if (i > 0) call << ", ";
							call << "p" << i << ": ";
							if (i < static_cast<unsigned>(fc.args_size()))
								call << visitUintExpr(fc.args(i));
							else
								call << "0";
						}
						call << "})";
					}
					else
					{
						call << target.name << "(";
						for (unsigned i = 0; i < target.numParams; i++)
						{
							if (i > 0) call << ", ";
							if (i < static_cast<unsigned>(fc.args_size()))
								call << visitUintExpr(fc.args(i));
							else
								call << "0";
						}
						call << ")";
					}
					result = call.str();
					break;
				}
			}
		}
		// Try calling a free function (always pure, callable from any context).
		// Skip UDVT-sig free functions: their params are MyUint, not uint256,
		// so a direct call here wouldn't type-check. They're reached via the
		// user-defined operator dispatch instead.
		if (!m_freeFunctions.empty())
		{
			unsigned ffIdx = fc.func_id() % m_freeFunctions.size();
			unsigned tries = 0;
			while (m_freeFunctions[ffIdx].useUdvtSig
				&& tries < m_freeFunctions.size())
			{
				ffIdx = (ffIdx + 1) % m_freeFunctions.size();
				tries++;
			}
			if (m_freeFunctions[ffIdx].useUdvtSig)
			{
				result = findVar(randomNumber());
				break;
			}
			auto const& ff = m_freeFunctions[ffIdx];
			std::ostringstream call;
			call << ff.name << "(";
			for (unsigned i = 0; i < ff.numParams; i++)
			{
				if (i > 0) call << ", ";
				if (i < static_cast<unsigned>(fc.args_size()))
					call << visitUintExpr(fc.args(i));
				else
					call << "0";
			}
			call << ")";
			result = call.str();
		}
		else
			result = findVar(randomNumber());
		break;
	}
	case Expression::kTypeConv:
	{
		auto const& tc = _e.type_conv();
		std::string inner = visitUintExpr(tc.arg());
		auto const& toType = tc.to_type();
		if (toType.type_oneof_case() == ElementaryType::kIntType)
		{
			unsigned w = (static_cast<unsigned>(toType.int_type().width()) % 32 + 1) * 8;
			if (toType.int_type().is_signed())
				// Signed round-trip: uint256 -> intN -> int256 -> uint256
				result = "uint256(int256(int" + std::to_string(w) + "(" + inner + ")))";
			else if (w < 256)
				// Unsigned narrowing + widening
				result = "uint256(uint" + std::to_string(w) + "(" + inner + "))";
			else
				result = inner;
		}
		else
			result = inner;
		break;
	}
	case Expression::kAbiEncode:
	{
		// Implement abi.encode/abi.encodePacked as hash to get a uint256
		auto const& ae = _e.abi_encode();
		std::ostringstream args;
		unsigned numArgs = std::min(static_cast<unsigned>(ae.args_size()), 3u);
		if (numArgs == 0)
			args << "uint256(0)";
		else
		{
			for (unsigned i = 0; i < numArgs; i++)
			{
				if (i > 0) args << ", ";
				args << visitUintExpr(ae.args(i));
			}
		}
		switch (ae.kind())
		{
		case AbiEncodeExpr::ENCODE:
			result = "uint256(keccak256(abi.encode(" + args.str() + ")))";
			break;
		case AbiEncodeExpr::ENCODE_PACKED:
		{
			// abi.encodePacked cannot pack bare literals — wrap each arg in uint256()
			std::ostringstream wrappedArgs;
			if (numArgs == 0)
				wrappedArgs << "uint256(0)";
			else
			{
				for (unsigned i = 0; i < numArgs; i++)
				{
					if (i > 0) wrappedArgs << ", ";
					wrappedArgs << "uint256(" << visitUintExpr(ae.args(i)) << ")";
				}
			}
			result = "uint256(keccak256(abi.encodePacked(" + wrappedArgs.str() + ")))";
			break;
		}
		case AbiEncodeExpr::ENCODE_WITH_SELECTOR:
			// Use a deterministic selector bytes4(0x12345678)
			result = "uint256(keccak256(abi.encodeWithSelector(bytes4(0x12345678), " + args.str() + ")))";
			break;
		case AbiEncodeExpr::ENCODE_WITH_SIGNATURE:
			result = "uint256(keccak256(abi.encodeWithSignature(\"foo(uint256)\", " + args.str() + ")))";
			break;
		}
		break;
	}
	case Expression::kStructAccess:
	{
		// Access a struct state variable's field
		auto structVars = allStructVars();
		if (!structVars.empty() && m_canReadState)
		{
			auto const& sa = _e.struct_access();
			unsigned varIdx = sa.struct_var().index() % structVars.size();
			auto const& [svName, structDefIdx] = structVars[varIdx];
			auto const& structDef = m_currentStructDefs[structDefIdx];

			// Find a uint-compatible field
			std::vector<unsigned> uintFields;
			for (unsigned k = 0; k < structDef.fields.size(); k++)
				if (structDef.fields[k].isUintCompatible)
					uintFields.push_back(k);

			if (!uintFields.empty())
			{
				unsigned fieldIdx = sa.field_idx() % uintFields.size();
				auto const& field = structDef.fields[uintFields[fieldIdx]];
				std::string access = svName + "." + field.name;
				// Widen to uint256 if needed
				if (field.typeStr != "uint256")
					result = "uint256(" + access + ")";
				else
					result = access;
			}
			else
				result = defaultUintLiteral();
		}
		else
			result = defaultUintLiteral();
		break;
	}
	case Expression::kEnumLit:
	{
		// Convert an enum member to uint256
		if (!m_currentEnumDefs.empty())
		{
			auto const& el = _e.enum_lit();
			unsigned enumIdx = el.enum_idx() % m_currentEnumDefs.size();
			auto const& ed = m_currentEnumDefs[enumIdx];
			unsigned memberIdx = el.member_idx() % ed.numMembers;
			result = "uint256(" + ed.name + "." + ed.memberNames[memberIdx] + ")";
		}
		else
			result = defaultUintLiteral();
		break;
	}
	case Expression::kEcrecover:
	{
		// ecrecover(bytes32, uint8, bytes32, bytes32) -> address; pure, never reverts
		// Wrap inner expressions with uint256() to avoid invalid bytes32(LITERAL) casts
		auto const& ec = _e.ecrecover();
		std::string hash = "bytes32(uint256(" + visitUintExpr(ec.hash()) + "))";
		std::string v = "uint8(27 + (" + visitUintExpr(ec.v()) + ") % 2)";
		std::string r = "bytes32(uint256(" + visitUintExpr(ec.r()) + "))";
		std::string s = "bytes32(uint256(" + visitUintExpr(ec.s()) + "))";
		result = "uint256(uint160(ecrecover(" + hash + ", " + v + ", " + r + ", " + s + ")))";
		break;
	}
	case Expression::kTypeInfo:
	{
		// type(uintN).min / type(uintN).max — pure, compile-time constants
		auto const& ti = _e.type_info();
		unsigned w = (static_cast<unsigned>(ti.int_type().width()) % 32 + 1) * 8;
		bool isSigned = ti.int_type().is_signed();
		std::string typeName = (isSigned ? "int" : "uint") + std::to_string(w);
		std::string typeExpr = "type(" + typeName + ")."
			+ (ti.kind() == TypeInfoExpr::MIN ? "min" : "max");
		// Signed types need int256 intermediate: uint256(int256(type(intN).min))
		if (isSigned)
			result = "uint256(int256(" + typeExpr + "))";
		else
			result = "uint256(" + typeExpr + ")";
		break;
	}
	case Expression::kIndexAccess:
	{
		// Index into a fixed-size array or mapping state variable
		auto const& ia = _e.index_access();
		if (!m_currentIndexableVars.empty() && m_canReadState)
		{
			unsigned hint = ia.base().has_var_ref() ? ia.base().var_ref().index() : randomNumber();
			unsigned varIdx = hint % m_currentIndexableVars.size();
			auto const& sv = m_currentIndexableVars[varIdx];
			std::string indexExpr = visitUintExpr(ia.index());

			if (sv.isFixedArray)
			{
				// Bounds-check with modulo to prevent out-of-bounds revert
				result = sv.name + "[" + indexExpr + " % " + std::to_string(sv.arrayLength) + "]";
			}
			else if (sv.isMapping)
			{
				// Mapping access is always safe (returns default for missing key)
				std::string key = indexExpr;
				if (sv.mappingKeyTypeStr != "uint256")
					key = sv.mappingKeyTypeStr + "(" + key + ")";
				result = sv.name + "[" + key + "]";
			}
			// Widen element to uint256 if needed
			if (!result.empty() && !sv.elementIsUint)
				result = "uint256(" + result + ")";
		}
		else
			result = findVar(randomNumber());
		break;
	}
	case Expression::kSuperCall:
	{
		// super.funcName(args...) — call a base contract's function
		if (m_currentContract >= m_contracts.size())
		{
			result = findVar(randomNumber());
			break;
		}
		auto const& sc = _e.super_call();
		auto const& cinfo = m_contracts[m_currentContract];

		// Collect callable non-private functions from all base contracts
		struct BaseFuncRef { unsigned contractIdx; unsigned funcIdx; };
		std::vector<BaseFuncRef> baseFuncs;
		for (unsigned baseIdx : cinfo.baseIndices)
		{
			auto const& base = m_contracts[baseIdx];
			for (unsigned fi = 0; fi < base.functions.size(); fi++)
			{
				auto const& bf = base.functions[fi];
				if (bf.vis == PRIVATE)
					continue;
				if (bf.returnsStruct || bf.returnTwo)
					continue;
				bool takesStruct = false;
				for (auto pt : bf.paramTypes)
					if (pt == PARAM_STRUCT) { takesStruct = true; break; }
				if (takesStruct)
					continue;
				// Check mutability compatibility
				bool canCall = true;
				if (m_currentMutability == PURE && bf.mut != PURE)
					canCall = false;
				if (m_currentMutability == VIEW && bf.mut != PURE && bf.mut != VIEW)
					canCall = false;
				if (canCall)
					baseFuncs.push_back({baseIdx, fi});
			}
		}
		if (!baseFuncs.empty())
		{
			unsigned idx = sc.func_idx() % baseFuncs.size();
			auto const& ref = baseFuncs[idx];
			auto const& target = m_contracts[ref.contractIdx].functions[ref.funcIdx];

			std::ostringstream call;
			call << "super." << target.name << "(";
			for (unsigned i = 0; i < target.numParams; i++)
			{
				if (i > 0) call << ", ";
				if (i < static_cast<unsigned>(sc.args_size()))
					call << visitUintExpr(sc.args(i));
				else
					call << "0";
			}
			call << ")";
			result = call.str();
		}
		else
			result = findVar(randomNumber());
		break;
	}
	case Expression::kLibMemberCall:
	{
		// Library member call via `using LibName for uint256`:
		// receiver.libFunc(remaining_args)
		auto const& lmc = _e.lib_member_call();

		// Find all callable library functions with >= 1 param
		struct LibFuncRef { unsigned contractIdx; unsigned funcIdx; };
		std::vector<LibFuncRef> libFuncs;
		for (unsigned ci = 0; ci < m_contracts.size(); ci++)
		{
			if (m_contracts[ci].kind != ContractDef::LIBRARY)
				continue;
			for (unsigned fi = 0; fi < m_contracts[ci].functions.size(); fi++)
			{
				auto const& lf = m_contracts[ci].functions[fi];
				if (lf.numParams < 1)
					continue;
				if (lf.returnsStruct || lf.returnTwo)
					continue;
				bool takesStruct = false;
				for (auto pt : lf.paramTypes)
					if (pt == PARAM_STRUCT) { takesStruct = true; break; }
				if (takesStruct)
					continue;
				bool canCall = true;
				if (m_currentMutability == PURE && lf.mut != PURE)
					canCall = false;
				if (m_currentMutability == VIEW && lf.mut != PURE && lf.mut != VIEW)
					canCall = false;
				if (canCall)
					libFuncs.push_back({ci, fi});
			}
		}
		if (!libFuncs.empty())
		{
			unsigned idx = lmc.func_idx() % libFuncs.size();
			auto const& ref = libFuncs[idx];
			auto const& target = m_contracts[ref.contractIdx].functions[ref.funcIdx];

			// Receiver is the implicit first argument
			std::string receiver = visitUintExpr(lmc.receiver());
			std::ostringstream call;
			call << receiver << "." << target.name << "(";
			// Remaining arguments (first param is the receiver)
			for (unsigned i = 1; i < target.numParams; i++)
			{
				if (i > 1) call << ", ";
				if ((i - 1) < static_cast<unsigned>(lmc.args_size()))
					call << visitUintExpr(lmc.args(i - 1));
				else
					call << "0";
			}
			call << ")";
			result = call.str();
		}
		else
			result = findVar(randomNumber());
		break;
	}
	case Expression::kConcat:
	{
		// bytes.concat() or string.concat() — hash result to uint256.
		// Named-arg form is always invalid (these builtins are variadic
		// with no parameter names) but exercises #16617.
		auto const& cc = _e.concat();
		unsigned numArgs = std::min(static_cast<unsigned>(cc.args_size()), 3u);
		bool named = cc.has_use_named_args() && cc.use_named_args();
		std::ostringstream args;
		if (numArgs == 0)
		{
			if (named)
				args << "{}";
			else
				args << (cc.kind() == ConcatExpr::STRING_CONCAT ? "\"\"" : "bytes(\"\")");
		}
		else
		{
			if (named) args << "{";
			for (unsigned i = 0; i < numArgs; i++)
			{
				if (i > 0) args << ", ";
				std::string inner = visitUintExpr(cc.args(i));
				std::string val = (cc.kind() == ConcatExpr::STRING_CONCAT)
					? "string(abi.encode(" + inner + "))"
					: "abi.encode(" + inner + ")";
				if (named)
					args << "a" << i << ": " << val;
				else
					args << val;
			}
			if (named) args << "}";
		}
		if (cc.kind() == ConcatExpr::BYTES_CONCAT)
			result = "uint256(keccak256(bytes.concat(" + args.str() + ")))";
		else
			result = "uint256(keccak256(bytes(string.concat(" + args.str() + "))))";
		break;
	}
	case Expression::kArrayLength:
	{
		// arr.length — read the length of a dynamic storage array
		if (!m_currentDynArrayVars.empty() && m_canReadState)
		{
			unsigned varIdx = _e.array_length().var_idx() % m_currentDynArrayVars.size();
			result = m_currentDynArrayVars[varIdx].name + ".length";
		}
		else
			result = defaultUintLiteral();
		break;
	}
	case Expression::kSelector:
	{
		// this.funcName.selector — get 4-byte function selector
		// `this.` is not allowed in pure functions
		if (m_currentMutability == PURE)
		{
			result = defaultUintLiteral();
			break;
		}
		auto const& sel = _e.selector();
		if (m_currentContract >= m_contracts.size())
		{
			result = defaultUintLiteral();
			break;
		}
		auto const& cinfo = m_contracts[m_currentContract];
		// Collect public/external functions
		std::vector<unsigned> pubExtFuncs;
		for (unsigned i = 0; i < cinfo.functions.size(); i++)
			if (cinfo.functions[i].vis == PUBLIC || cinfo.functions[i].vis == EXTERNAL)
				pubExtFuncs.push_back(i);
		if (!pubExtFuncs.empty())
		{
			unsigned idx = sel.func_idx() % pubExtFuncs.size();
			auto const& target = cinfo.functions[pubExtFuncs[idx]];
			result = "uint256(uint32(this." + target.name + ".selector))";
		}
		else
			result = defaultUintLiteral();
		break;
	}
	case Expression::kAbiDecode:
	{
		// abi.decode(abi.encode(val), (uint256)) — round-trip encode/decode
		std::string val = visitUintExpr(_e.abi_decode().value());
		result = "abi.decode(abi.encode(" + val + "), (uint256))";
		break;
	}
	case Expression::kUdvtExpr:
	{
		// UDVT wrap/unwrap: MyUint.wrap(val) / MyUint.unwrap(MyUint.wrap(val))
		if (!m_hasUdvt)
		{
			result = defaultUintLiteral();
			break;
		}
		auto const& ue = _e.udvt_expr();
		std::string inner = visitUintExpr(ue.inner());
		if (ue.wrap_only())
			// Wrap then immediately unwrap to get back to uint256
			result = "MyUint.unwrap(MyUint.wrap(" + inner + "))";
		else
		{
			// Use a user-defined operator via wrap, then unwrap
			// MyUint.unwrap(MyUint.wrap(a) + MyUint.wrap(b))
			std::string b = defaultUintLiteral();
			result = "MyUint.unwrap(MyUint.wrap(" + inner + ") + MyUint.wrap(" + b + "))";
		}
		break;
	}
	case Expression::kArrayLit:
	{
		// Build an inline-array literal, index into it, reduce to uint256.
		// Uniform kinds produce valid programs — good for optimizer
		// differential testing. Mixed kinds produce type errors that
		// exercise the mobile-type inference path (ICE history).
		auto const& al = _e.array_lit();
		unsigned n = std::min(static_cast<unsigned>(al.elems_size()), 4u);
		if (n == 0) n = 1;
		unsigned idx = (al.has_index() ? al.index() : 0u) % n;
		std::vector<std::string> raw;
		raw.reserve(n);
		for (unsigned i = 0; i < n; i++)
		{
			if (static_cast<int>(i) < al.elems_size())
				raw.push_back(visitUintExpr(al.elems(i)));
			else
				raw.push_back(defaultUintLiteral());
		}
		auto join = [](std::vector<std::string> const& xs) {
			std::ostringstream o;
			for (size_t i = 0; i < xs.size(); i++)
			{
				if (i > 0) o << ", ";
				o << xs[i];
			}
			return o.str();
		};
		std::ostringstream lit;
		switch (al.kind())
		{
		case ArrayLiteralExpr::UINT256:
		{
			std::vector<std::string> cast;
			for (unsigned i = 0; i < n; i++)
				cast.push_back(i == 0 ? ("uint256(" + raw[i] + ")") : raw[i]);
			lit << "[" << join(cast) << "][" << idx << "]";
			result = lit.str();
			break;
		}
		case ArrayLiteralExpr::INT256:
		{
			std::vector<std::string> cast;
			for (unsigned i = 0; i < n; i++)
				cast.push_back(i == 0 ? ("int256(int256(int256(0)) + int256(uint256(" + raw[i] + ") % (2**255)))")
				                      : ("int256(uint256(" + raw[i] + ") % (2**255))"));
			lit << "uint256(" << "[" << join(cast) << "][" << idx << "])";
			result = lit.str();
			break;
		}
		case ArrayLiteralExpr::ADDRESS:
		{
			std::vector<std::string> cast;
			for (unsigned i = 0; i < n; i++)
			{
				std::string a = "address(uint160(" + raw[i] + "))";
				cast.push_back(i == 0 ? a : a);
			}
			lit << "uint256(uint160([" << join(cast) << "][" << idx << "]))";
			result = lit.str();
			break;
		}
		case ArrayLiteralExpr::BYTES32:
		{
			std::vector<std::string> cast;
			for (unsigned i = 0; i < n; i++)
				cast.push_back("bytes32(" + raw[i] + ")");
			lit << "uint256([" << join(cast) << "][" << idx << "])";
			result = lit.str();
			break;
		}
		case ArrayLiteralExpr::BOOL:
		{
			std::vector<std::string> cast;
			for (unsigned i = 0; i < n; i++)
				cast.push_back("((" + raw[i] + ") != 0)");
			lit << "([" << join(cast) << "][" << idx << "] ? uint256(1) : uint256(0))";
			result = lit.str();
			break;
		}
		case ArrayLiteralExpr::MIXED_SIGN:
		{
			// [uint(e0), int(-e1), uint(e2), ...] — type-error surface.
			std::vector<std::string> cast;
			for (unsigned i = 0; i < n; i++)
			{
				if (i % 2 == 0)
					cast.push_back("uint256(" + raw[i] + ")");
				else
					cast.push_back("int256(-int256(uint256(" + raw[i] + ") % (2**255)))");
			}
			lit << "uint256([" << join(cast) << "][" << idx << "])";
			result = lit.str();
			break;
		}
		case ArrayLiteralExpr::MIXED_WIDTH:
		{
			// [uint8(e0), uint256(e1), uint16(e2), ...]
			static char const* const widths[] = {"uint8", "uint256", "uint16", "uint128"};
			std::vector<std::string> cast;
			for (unsigned i = 0; i < n; i++)
				cast.push_back(std::string(widths[i % 4]) + "(" + raw[i] + ")");
			lit << "uint256([" << join(cast) << "][" << idx << "])";
			result = lit.str();
			break;
		}
		case ArrayLiteralExpr::MIXED_BYTES:
		{
			// [bytes1(..), bytes2(..), bytes4(..), ...]
			static char const* const widths[] = {"bytes1", "bytes2", "bytes4", "bytes8"};
			std::vector<std::string> cast;
			for (unsigned i = 0; i < n; i++)
				cast.push_back(std::string(widths[i % 4])
					+ "(uint" + std::to_string(8 << (i % 4)) + "(" + raw[i] + "))");
			lit << "uint256(uint64(bytes8([" << join(cast) << "][" << idx << "])))";
			result = lit.str();
			break;
		}
		case ArrayLiteralExpr::NESTED:
		{
			// [[uint(e0)], [uint(e1)], ...][outerIdx][0]
			std::vector<std::string> outer;
			for (unsigned i = 0; i < n; i++)
				outer.push_back(i == 0 ? ("[uint256(" + raw[i] + ")]") : ("[" + raw[i] + "]"));
			lit << "[" << join(outer) << "][" << idx << "][0]";
			result = lit.str();
			break;
		}
		}
		break;
	}
	case Expression::kAbiEncodeCall:
	{
		// abi.encodeCall(this.func, (args)) — type-safe call encoding
		// `this.` is not allowed in pure functions
		if (m_currentMutability == PURE)
		{
			result = defaultUintLiteral();
			break;
		}
		auto const& aec = _e.abi_encode_call();
		if (m_currentContract >= m_contracts.size())
		{
			result = defaultUintLiteral();
			break;
		}
		auto const& cinfo = m_contracts[m_currentContract];
		// Find external functions (abi.encodeCall requires function pointer)
		std::vector<unsigned> extFuncs;
		for (unsigned i = 0; i < cinfo.functions.size(); i++)
			if (cinfo.functions[i].vis == EXTERNAL)
				extFuncs.push_back(i);
		if (!extFuncs.empty())
		{
			unsigned idx = aec.func_id() % extFuncs.size();
			auto const& target = cinfo.functions[extFuncs[idx]];
			// Build args matching function params
			std::ostringstream argsStr;
			argsStr << "(";
			for (unsigned i = 0; i < target.numParams; i++)
			{
				if (i > 0) argsStr << ", ";
				ParamType pt = (i < target.paramTypes.size()) ? target.paramTypes[i] : PARAM_UINT256;
				std::string val = (i < static_cast<unsigned>(aec.args_size()))
					? visitUintExpr(aec.args(i)) : "0";
				switch (pt)
				{
				case PARAM_BOOL:
					argsStr << val << " % 2 == 1";
					break;
				case PARAM_ADDRESS:
					argsStr << "address(uint160(" << val << "))";
					break;
				case PARAM_BYTES32:
					argsStr << "bytes32(" << val << ")";
					break;
				default:
					argsStr << val;
					break;
				}
			}
			argsStr << ")";
			result = "uint256(keccak256(abi.encodeCall(this." + target.name + ", " + argsStr.str() + ")))";
		}
		else
			result = defaultUintLiteral();
		break;
	}
	default:
		result = findVar(randomNumber());
		break;
	}

	m_exprDepth--;
	return result.empty() ? defaultUintLiteral() : result;
}

std::string ProtoConverter::visitBoolExpr(Expression const& _e)
{
	if (m_exprDepth >= s_maxExprDepth)
		return defaultBoolLiteral();

	m_exprDepth++;
	std::string result;

	switch (_e.expr_oneof_case())
	{
	case Expression::kLit:
	{
		auto const& lit = _e.lit();
		if (lit.has_bool_lit())
			result = lit.bool_lit().val() ? "true" : "false";
		else
			result = defaultBoolLiteral();
		break;
	}
	case Expression::kBinOp:
	{
		auto const& op = _e.bin_op();
		if (isComparisonOp(op.op()))
		{
			result = visitUintExpr(op.left()) + " " +
				comparisonOpStr(op.op()) + " " +
				visitUintExpr(op.right());
		}
		else if (isLogicalOp(op.op()))
		{
			result = visitBoolExpr(op.left()) + " " +
				logicalOpStr(op.op()) + " " +
				visitBoolExpr(op.right());
		}
		else
		{
			// Arithmetic/bitwise op in bool context: generate a runtime-
			// dependent comparison instead of a potentially trivial
			// "literal != 0" when no variables are in scope.
			result = defaultBoolLiteral();
		}
		break;
	}
	case Expression::kUnOp:
	{
		auto const& op = _e.un_op();
		if (op.op() == UnaryOp::LNOT)
			result = "!(" + visitBoolExpr(op.operand()) + ")";
		else
		{
			// Non-logical unary in bool context: same as above.
			result = defaultBoolLiteral();
		}
		break;
	}
	case Expression::kTernary:
		result = "(" + visitBoolExpr(_e.ternary().cond()) + " ? " +
			visitBoolExpr(_e.ternary().true_val()) + " : " +
			visitBoolExpr(_e.ternary().false_val()) + ")";
		break;
	default:
		// For any other expression type, generate a runtime comparison.
		result = defaultBoolLiteral();
		break;
	}

	m_exprDepth--;
	return result.empty() ? defaultBoolLiteral() : result;
}

// =====================================================================
// Test contract generation
// =====================================================================

std::string ProtoConverter::generateTestContract()
{
	std::ostringstream o;
	o << "contract C {\n";

	// Attach library functions via using-for so they can be called
	// as member functions on uint256 values.
	for (auto const& ci : m_contracts)
	{
		if (ci.kind != ContractDef::LIBRARY)
			continue;
		bool hasCallable = false;
		for (auto const& lf : ci.functions)
			if (lf.numParams >= 1)
			{
				hasCallable = true;
				break;
			}
		if (hasCallable)
			o << "\tusing " << ci.name << " for uint256;\n";
	}

	// Calldataload helper for extracting random values from extra calldata
	o << "\tfunction _cdl(uint256 _o) private pure returns (uint256 _v) {\n";
	o << "\t\tassembly { _v := calldataload(_o) }\n";
	o << "\t}\n";

	o << "\tfunction test() public payable returns (uint256) {\n";
	o << "\t\tuint256 _r = 0;\n";

	unsigned callIdx = 0;
	// Track position in extra calldata (after the 4-byte selector)
	unsigned paramOffset = 0;

	// For each non-library contract, create an instance inside try/catch
	// and call its functions.  If the constructor reverts, we skip that
	// contract but continue testing the others.
	for (auto const& ci : m_contracts)
	{
		if (ci.kind == ContractDef::LIBRARY)
			continue;
		if (ci.functions.empty())
			continue;

		std::string instVar = "_t" + ci.name;

		// Wrap construction + calls in a try/catch so a reverting
		// constructor doesn't abort the entire test.
		if (m_useCreate2)
		{
			o << "\t\ttry new " << ci.name << "{salt: bytes32(uint256(0x"
			  << m_create2SaltHex << ") ^ " << callIdx << ")}(";
		}
		else
		{
			o << "\t\ttry new " << ci.name << "(";
		}
		// Pass constructor parameter if this contract has one
		if (ci.hasCtorParam)
		{
			o << "_cdl(" << (4 + paramOffset * 32) << ")";
			paramOffset++;
		}
		o << ") returns (" << ci.name << " " << instVar << ") {\n";

		// Call each public/external function via low-level call, staticcall,
		// and delegatecall for differential testing
		for (auto const& fi : ci.functions)
		{
			if (fi.vis != PUBLIC && fi.vis != EXTERNAL)
				continue;

			// Build signature string with actual param types
			std::string sig = fi.name + "(";
			for (unsigned i = 0; i < fi.numParams; i++)
			{
				if (i > 0) sig += ",";
				ParamType pt = (i < fi.paramTypes.size()) ? fi.paramTypes[i] : PARAM_UINT256;
				sig += paramTypeAbiStr(pt);
			}
			sig += ")";

			// Helper to emit the encoded arguments
			auto emitArgs = [&](unsigned paramBase)
			{
				for (unsigned i = 0; i < fi.numParams; i++)
				{
					ParamType pt = (i < fi.paramTypes.size()) ? fi.paramTypes[i] : PARAM_UINT256;
					std::string raw = "_cdl(" + std::to_string(4 + (paramBase + i) * 32) + ")";
					switch (pt)
					{
					case PARAM_BOOL:
						o << ", " << raw << " % 2 == 1";
						break;
					case PARAM_ADDRESS:
						o << ", address(uint160(" << raw << "))";
						break;
					case PARAM_BYTES32:
						o << ", bytes32(" << raw << ")";
						break;
					default:
						o << ", " << raw;
						break;
					}
				}
			};

			// Helper to emit result decoding
			auto emitDecode = [&](std::string const& boolV, std::string const& dataV)
			{
				if (fi.returnTwo)
				{
					o << "\t\t\tif (" << boolV << " && " << dataV << ".length == 64) {\n";
					o << "\t\t\t\t(uint256 _a" << callIdx << ", uint256 _b" << callIdx
					  << ") = abi.decode(" << dataV << ", (uint256, uint256));\n";
					o << "\t\t\t\t_r ^= _a" << callIdx << " ^ _b" << callIdx << ";\n";
					o << "\t\t\t}\n";
				}
				else
					o << "\t\t\tif (" << boolV << " && " << dataV << ".length == 32) "
					  << "_r ^= abi.decode(" << dataV << ", (uint256));\n";
			};

			// 1. Regular .call() — with value for payable functions
			std::string boolVar = "_s" + std::to_string(callIdx);
			std::string dataVar = "_d" + std::to_string(callIdx);
			callIdx++;

			o << "\t\t\t(bool " << boolVar << ", bytes memory " << dataVar
			  << ") = address(" << instVar << ")";
			if (fi.mut == PAYABLE)
				o << ".call{value: " << (callIdx * 7 + 1) << "}";
			else
				o << ".call";
			o << "(abi.encodeWithSignature(\"" << sig << "\"";
			emitArgs(paramOffset);
			paramOffset += fi.numParams;
			o << "));\n";
			emitDecode(boolVar, dataVar);

			// 2. .staticcall() for view/pure functions
			if (fi.mut == PURE || fi.mut == VIEW)
			{
				std::string scBool = "_ss" + std::to_string(callIdx);
				std::string scData = "_sd" + std::to_string(callIdx);
				callIdx++;

				o << "\t\t\t(bool " << scBool << ", bytes memory " << scData
				  << ") = address(" << instVar
				  << ").staticcall(abi.encodeWithSignature(\"" << sig << "\"";
				emitArgs(paramOffset);
				paramOffset += fi.numParams;
				o << "));\n";
				emitDecode(scBool, scData);
			}

			// 3. .delegatecall() for non-payable functions (every other function)
			if (callIdx % 3 == 0 && fi.mut != PAYABLE)
			{
				std::string dcBool = "_ds" + std::to_string(callIdx);
				std::string dcData = "_dd" + std::to_string(callIdx);
				callIdx++;

				o << "\t\t\t(bool " << dcBool << ", bytes memory " << dcData
				  << ") = address(" << instVar
				  << ").delegatecall(abi.encodeWithSignature(\"" << sig << "\"";
				emitArgs(paramOffset);
				paramOffset += fi.numParams;
				o << "));\n";
				emitDecode(dcBool, dcData);
			}

			// 4. Typed external call (direct instance.func() call) — every other function.
			// This tests the high-level ABI encoding/decoding codegen path.
			if (callIdx % 2 == 0 && fi.vis == EXTERNAL)
			{
				o << "\t\t\ttry " << instVar << "." << fi.name << "(";
				for (unsigned i = 0; i < fi.numParams; i++)
				{
					if (i > 0) o << ", ";
					ParamType pt = (i < fi.paramTypes.size()) ? fi.paramTypes[i] : PARAM_UINT256;
					std::string raw = "_cdl(" + std::to_string(4 + (paramOffset + i) * 32) + ")";
					switch (pt)
					{
					case PARAM_BOOL:
						o << raw << " % 2 == 1";
						break;
					case PARAM_ADDRESS:
						o << "address(uint160(" << raw << "))";
						break;
					case PARAM_BYTES32:
						o << "bytes32(" << raw << ")";
						break;
					default:
						o << raw;
						break;
					}
				}
				paramOffset += fi.numParams;
				if (fi.returnTwo)
				{
					o << ") returns (uint256 _ta" << callIdx << ", uint256 _tb" << callIdx << ") {\n";
					o << "\t\t\t\t_r ^= _ta" << callIdx << " ^ _tb" << callIdx << ";\n";
				}
				else
				{
					o << ") returns (uint256 _tv" << callIdx << ") {\n";
					o << "\t\t\t\t_r ^= _tv" << callIdx << ";\n";
				}
				o << "\t\t\t} catch {}\n";
				callIdx++;
			}
		}

		// Close try block, empty catch (skip this contract on revert)
		o << "\t\t} catch {}\n";
	}

	// For library contracts, call internal functions via using-for member syntax.
	// Library functions are always internal, so they must be called as
	// receiver.funcName(remaining_args) where the first param is the receiver.
	for (auto const& ci : m_contracts)
	{
		if (ci.kind != ContractDef::LIBRARY)
			continue;

		for (auto const& fi : ci.functions)
		{
			if (fi.numParams < 1)
				continue; // Can't call via member syntax without a receiver param
			if (fi.returnTwo)
				continue; // Skip functions returning tuples — can't XOR with uint256
			// receiver.funcName(remaining_args)
			o << "\t\t_r ^= _cdl(" << (4 + paramOffset * 32) << ")."
			  << fi.name << "(";
			paramOffset++;
			for (unsigned i = 1; i < fi.numParams; i++)
			{
				if (i > 1) o << ", ";
				o << "_cdl(" << (4 + (paramOffset) * 32) << ")";
				paramOffset++;
			}
			o << ");\n";
		}
	}

	// Cross-contract interaction: if we have multiple deployed contracts,
	// call functions of the second contract from the first contract's context
	// by passing addresses around. This tests inter-contract state flows.
	{
		std::vector<unsigned> nonLibContracts;
		for (unsigned i = 0; i < m_contracts.size(); i++)
			if (m_contracts[i].kind != ContractDef::LIBRARY && !m_contracts[i].functions.empty())
				nonLibContracts.push_back(i);

		if (nonLibContracts.size() >= 2)
		{
			auto const& ciA = m_contracts[nonLibContracts[0]];
			auto const& ciB = m_contracts[nonLibContracts[1]];
			std::string instA = "_t" + ciA.name;
			std::string instB = "_t" + ciB.name;

			// Call B's first public/external function from A's address context
			// using low-level call with A's address as intermediary
			for (auto const& fi : ciB.functions)
			{
				if (fi.vis != PUBLIC && fi.vis != EXTERNAL)
					continue;
				// Build signature
				std::string sig = fi.name + "(";
				for (unsigned i = 0; i < fi.numParams; i++)
				{
					if (i > 0) sig += ",";
					ParamType pt = (i < fi.paramTypes.size()) ? fi.paramTypes[i] : PARAM_UINT256;
					sig += paramTypeAbiStr(pt);
				}
				sig += ")";

				std::string boolVar = "_xs" + std::to_string(callIdx);
				std::string dataVar = "_xd" + std::to_string(callIdx);
				callIdx++;

				o << "\t\t(bool " << boolVar << ", bytes memory " << dataVar
				  << ") = address(" << instB
				  << ").call(abi.encodeWithSignature(\"" << sig << "\"";
				for (unsigned i = 0; i < fi.numParams; i++)
				{
					o << ", _cdl(" << (4 + (paramOffset + i) * 32) << ")";
				}
				paramOffset += fi.numParams;
				o << "));\n";
				if (!fi.returnTwo)
					o << "\t\tif (" << boolVar << " && " << dataVar << ".length == 32) "
					  << "_r ^= abi.decode(" << dataVar << ", (uint256));\n";
				break; // Only do first function to keep code size manageable
			}
		}
	}

	o << "\t\treturn _r;\n";
	o << "\t}\n";
	o << "}\n";
	return o.str();
}

// =====================================================================
// Type helpers
// =====================================================================

std::string ProtoConverter::elementaryTypeStr(ElementaryType const& _t)
{
	switch (_t.type_oneof_case())
	{
	case ElementaryType::kBoolType:
		return "bool";
	case ElementaryType::kIntType:
	{
		// All 32 valid widths: (enum_value + 1) * 8
		unsigned w = (static_cast<unsigned>(_t.int_type().width()) % 32 + 1) * 8;
		return (_t.int_type().is_signed() ? "int" : "uint") + std::to_string(w);
	}
	case ElementaryType::kAddressPayable:
		return _t.address_payable() ? "address payable" : "address";
	case ElementaryType::kFixedBytes:
	{
		// All 32 valid widths: enum_value + 1
		unsigned w = static_cast<unsigned>(_t.fixed_bytes().width()) % 32 + 1;
		return "bytes" + std::to_string(w);
	}
	case ElementaryType::kIsString:
		return _t.is_string() ? "string" : "bytes";
	default:
		return "uint256";
	}
}

std::string ProtoConverter::elementaryTypeStr(TypeName const& _t)
{
	switch (_t.type_oneof_case())
	{
	case TypeName::kElementary:
		return elementaryTypeStr(_t.elementary());
	case TypeName::kArray:
	{
		std::string base = elementaryTypeStr(_t.array().base());
		// Expression-valued size takes priority — it renders `T[expr]`
		// regardless of whether `length` is set. The expression is a
		// non-constant that fails type-check but trips the targeted
		// magic-member ICE paths (#16615 and siblings).
		if (_t.array().has_size_expr()
			&& _t.array().size_expr().kind() != ArraySizeExpr::BUCKET)
			return base + "[" + arraySizeExprStr(_t.array().size_expr()) + "]";
		if (_t.array().has_length())
			return base + "[" + arraySizeBucket(_t.array().length()).first + "]";
		return base + "[]";
	}
	case TypeName::kMapping:
	{
		std::string key = elementaryTypeStr(_t.mapping().key());
		std::string val = elementaryTypeStr(_t.mapping().value());
		// Mapping keys must be elementary (not string/bytes/dynamic)
		// Simplify: use uint256 for key if the type is dynamic
		if (key == "string" || key == "bytes")
			key = "uint256";
		// Mapping keys cannot be "address payable", use "address" instead
		if (key == "address payable")
			key = "address";
		return "mapping(" + key + " => " + val + ")";
	}
	default:
		return "uint256";
	}
}

std::pair<std::string, unsigned> ProtoConverter::arraySizeBucket(uint32_t _raw)
{
	unsigned bucket = _raw % 16;
	if (bucket < 10)
	{
		unsigned n = std::max(1u, _raw % 10);
		return {std::to_string(n), n};
	}
	static char const* const s_bigLiterals[6] = {
		"134217729",                                                                               // 2^27 + 1 — ABI-encoded size overflow
		"170141183460469231731687303715884105728",                                                 // 2^127
		"340282366920938463463374607431768211456",                                                 // 2^128
		"340282366920938463463374607431768211458",                                                 // 2^128 + 2
		"1701411834604692317316873037158841057281",
		"115792089237316195423570985008687907853269984665640564039457584007913129639935",         // 2^256 - 1
	};
	return {s_bigLiterals[bucket - 10], 1u};
}

std::string ProtoConverter::arraySizeExprStr(ArraySizeExpr const& _e)
{
	switch (_e.kind())
	{
	case ArraySizeExpr::ABI_SUBSCRIPT:   return "uint(abi(\"\")[0])";
	case ArraySizeExpr::BLOCK_SUBSCRIPT: return "uint(block[0])";
	case ArraySizeExpr::MSG_SUBSCRIPT:   return "uint(msg[0])";
	case ArraySizeExpr::TX_SUBSCRIPT:    return "uint(tx[0])";
	case ArraySizeExpr::ABI_CALL:        return "uint(abi())";
	case ArraySizeExpr::TYPE_INDEX:      return "uint(type(uint256)[0])";
	case ArraySizeExpr::BUCKET:          break;
	}
	return "1";
}

bool ProtoConverter::isUintType(TypeName const& _t)
{
	if (_t.type_oneof_case() != TypeName::kElementary)
		return false;
	return isUintType(_t.elementary());
}

bool ProtoConverter::isUintType(ElementaryType const& _t)
{
	if (_t.type_oneof_case() != ElementaryType::kIntType)
		return false;
	return !_t.int_type().is_signed();
}

// =====================================================================
// Scope management
// =====================================================================

void ProtoConverter::pushScope()
{
	m_scopeStack.emplace_back();
	m_structLocalsStack.emplace_back();
}

void ProtoConverter::popScope()
{
	if (!m_scopeStack.empty())
		m_scopeStack.pop_back();
	if (!m_structLocalsStack.empty())
		m_structLocalsStack.pop_back();
}

void ProtoConverter::addVar(std::string const& _name)
{
	if (!m_scopeStack.empty())
		m_scopeStack.back().push_back(_name);
}

std::vector<std::string> ProtoConverter::allUintVars()
{
	std::vector<std::string> vars;
	for (auto const& scope : m_scopeStack)
		for (auto const& v : scope)
			vars.push_back(v);
	if (m_canReadState)
		for (auto const& sv : m_currentUintStateVars)
			vars.push_back(sv);
	return vars;
}

std::vector<std::pair<std::string, unsigned>> ProtoConverter::allStructVars()
{
	if (m_canReadState)
		return m_currentStructStateVars;
	return {};
}

std::vector<ProtoConverter::StructLocalInfo> ProtoConverter::allStructLocals()
{
	std::vector<StructLocalInfo> out;
	for (auto const& scope : m_structLocalsStack)
		for (auto const& l : scope)
			out.push_back(l);
	return out;
}

std::vector<unsigned> ProtoConverter::eligibleMemoryStructs()
{
	std::vector<unsigned> out;
	for (unsigned i = 0; i < m_currentStructDefs.size(); i++)
	{
		auto const& sd = m_currentStructDefs[i];
		if (sd.fields.empty())
			continue;
		bool allUint = true;
		for (auto const& f : sd.fields)
			if (!f.isUintCompatible)
			{
				allUint = false;
				break;
			}
		if (allUint)
			out.push_back(i);
	}
	return out;
}

std::string ProtoConverter::findVar(uint32_t _hint)
{
	auto vars = allUintVars();
	if (vars.empty())
		return defaultUintLiteral();
	return vars[_hint % vars.size()];
}

std::string ProtoConverter::findLVar(uint32_t _hint)
{
	// Local variables and function parameters (from scope stack, not state
	// vars) for lvalue operations like ++/--/assignment.
	std::vector<std::string> vars;
	for (auto const& scope : m_scopeStack)
		for (auto const& v : scope)
			vars.push_back(v);
	if (vars.empty())
		return ""; // Return empty to signal no lvalue available
	return vars[_hint % vars.size()];
}

void ProtoConverter::collectInheritedInfo(ContractInfo const& _cinfo)
{
	bool isLibrary = (_cinfo.kind == ContractDef::LIBRARY);

	m_currentUintStateVars.clear();
	m_currentStructStateVars.clear();
	m_currentIndexableVars.clear();
	m_currentDynArrayVars.clear();
	m_currentEvents = _cinfo.events;
	m_currentErrors = _cinfo.errors;
	m_currentStructDefs = _cinfo.structDefs;
	m_currentEnumDefs = _cinfo.enumDefs;

	// Current contract's own state vars — structDefIdx is relative to
	// _cinfo.structDefs which is already in m_currentStructDefs, so no offset.
	if (m_canReadState && !isLibrary)
	{
		for (auto const& sv : _cinfo.stateVars)
		{
			if (sv.isUint)
				m_currentUintStateVars.push_back(sv.name);
			if (sv.isStruct)
				m_currentStructStateVars.emplace_back(sv.name, sv.structDefIdx);
			if ((sv.isFixedArray || sv.isMapping) && sv.elementIsUint)
				m_currentIndexableVars.push_back(sv);
			if (sv.isArray && !sv.isFixedArray)
				m_currentDynArrayVars.push_back(sv);
		}
	}

	// Walk full inheritance chain across all bases (BFS to handle multiple bases)
	std::vector<unsigned> visited;
	std::vector<unsigned> queue;
	for (unsigned b : _cinfo.baseIndices)
		queue.push_back(b);

	while (!queue.empty())
	{
		unsigned baseIdx = queue.front();
		queue.erase(queue.begin());

		// Avoid visiting the same base twice (possible with multi-path inheritance)
		bool alreadyVisited = false;
		for (unsigned v : visited)
			if (v == baseIdx)
			{
				alreadyVisited = true;
				break;
			}
		if (alreadyVisited)
			continue;
		visited.push_back(baseIdx);

		auto const& baseInfo = m_contracts[baseIdx];

		// Inherited state vars — structDefIdx must be offset because base
		// struct defs are appended after what's already in m_currentStructDefs.
		if (m_canReadState && !isLibrary)
		{
			unsigned structOffset = m_currentStructDefs.size();
			for (auto const& sv : baseInfo.stateVars)
			{
				if (sv.isUint)
					m_currentUintStateVars.push_back(sv.name);
				if (sv.isStruct)
					m_currentStructStateVars.emplace_back(sv.name, sv.structDefIdx + structOffset);
				if ((sv.isFixedArray || sv.isMapping) && sv.elementIsUint)
					m_currentIndexableVars.push_back(sv);
				if (sv.isArray && !sv.isFixedArray)
					m_currentDynArrayVars.push_back(sv);
			}
		}

		// Inherit events and errors
		for (auto const& ev : baseInfo.events)
			m_currentEvents.push_back(ev);
		for (auto const& err : baseInfo.errors)
			m_currentErrors.push_back(err);

		// Inherit struct and enum definitions
		for (auto const& sd : baseInfo.structDefs)
			m_currentStructDefs.push_back(sd);
		for (auto const& ed : baseInfo.enumDefs)
			m_currentEnumDefs.push_back(ed);

		// Continue up the chain
		for (unsigned b : baseInfo.baseIndices)
			queue.push_back(b);
	}
}

// =====================================================================
// Helpers
// =====================================================================

std::string ProtoConverter::setupAndVisitBlock(
	Block const& _body,
	ContractInfo const& _cinfo,
	StateMutability _mut,
	unsigned _indentLevel
)
{
	m_canReadState = (_mut == VIEW || _mut == NONPAYABLE || _mut == PAYABLE);
	m_currentMutability = _mut;
	m_inConstructor = false;
	m_canReturn = false;
	m_currentReturnsTwo = false;
	m_currentStructReturnType.clear();
	m_currentStructReturnFieldCount = 0;
	m_currentFuncIdx = 0;
	collectInheritedInfo(_cinfo);

	pushScope();
	m_localVarCount = 0;
	m_varCounter = 0;
	m_indentLevel = _indentLevel;
	m_stmtDepth = 0;
	std::string result = visitBlock(_body);
	popScope();
	return result;
}

std::string ProtoConverter::indent()
{
	return std::string(m_indentLevel, '\t');
}

unsigned ProtoConverter::randomNumber()
{
	if (m_randomGen)
		return m_randomGen->operator()();
	return 0;
}

std::string ProtoConverter::defaultUintLiteral()
{
	// Vary the fallback literal using the RNG so that expressions don't all
	// collapse to the same value. This improves fuzzer coverage by producing
	// non-trivial conditions and arithmetic even at max expression depth.
	static constexpr unsigned literals[] = {0, 1, 2, 7, 42, 255, 997};
	return std::to_string(literals[randomNumber() % 7]);
}

std::string ProtoConverter::defaultBoolLiteral()
{
	// In pure functions we can't access runtime state, so use true/false.
	if (m_currentMutability == PURE)
		return (randomNumber() % 2 == 0) ? "true" : "false";

	// Generate a comparison between two runtime values so conditions are
	// non-trivial and actually depend on execution context. This avoids
	// degenerate "if (0 != 0)" patterns.
	static constexpr const char* lhsExprs[] = {
		"uint256(uint160(msg.sender))",
		"block.timestamp",
		"block.number",
		"uint256(uint160(tx.origin))",
		"block.prevrandao",
	};
	static constexpr const char* rhsExprs[] = {
		"uint256(uint160(address(block.coinbase)))",
		"block.chainid",
		"block.basefee",
		"block.blobbasefee",
		"uint256(blockhash(0))",
		"uint256(0)",
	};
	static constexpr const char* cmpOps[] = {
		" != ", " == ", " < ", " > ", " <= ", " >= ",
	};
	unsigned r = randomNumber();
	unsigned numLhs = m_inReceive ? 4 : 5;
	std::string lhs = lhsExprs[r % numLhs];
	std::string rhs = rhsExprs[(r / numLhs) % 6];
	std::string op = cmpOps[(r / (numLhs * 6)) % 6];
	return lhs + op + rhs;
}

// =====================================================================
// Operator classification and stringification
// =====================================================================

bool ProtoConverter::isArithmeticOp(BinaryOp::Op _op)
{
	return _op == BinaryOp::ADD || _op == BinaryOp::SUB ||
		_op == BinaryOp::MUL || _op == BinaryOp::DIV ||
		_op == BinaryOp::MOD || _op == BinaryOp::EXP;
}

bool ProtoConverter::isBitwiseOp(BinaryOp::Op _op)
{
	return _op == BinaryOp::BIT_AND || _op == BinaryOp::BIT_OR ||
		_op == BinaryOp::BIT_XOR || _op == BinaryOp::SHL ||
		_op == BinaryOp::SHR;
}

bool ProtoConverter::isComparisonOp(BinaryOp::Op _op)
{
	return _op == BinaryOp::LT || _op == BinaryOp::GT ||
		_op == BinaryOp::LTE || _op == BinaryOp::GTE ||
		_op == BinaryOp::EQ || _op == BinaryOp::NEQ;
}

bool ProtoConverter::isLogicalOp(BinaryOp::Op _op)
{
	return _op == BinaryOp::AND || _op == BinaryOp::OR;
}

std::string ProtoConverter::arithmeticOpStr(BinaryOp::Op _op)
{
	switch (_op)
	{
	case BinaryOp::ADD: return "+";
	case BinaryOp::SUB: return "-";
	case BinaryOp::MUL: return "*";
	case BinaryOp::DIV: return "/";
	case BinaryOp::MOD: return "%";
	case BinaryOp::EXP: return "**";
	default: return "+";
	}
}

std::string ProtoConverter::bitwiseOpStr(BinaryOp::Op _op)
{
	switch (_op)
	{
	case BinaryOp::BIT_AND: return "&";
	case BinaryOp::BIT_OR: return "|";
	case BinaryOp::BIT_XOR: return "^";
	case BinaryOp::SHL: return "<<";
	case BinaryOp::SHR: return ">>";
	default: return "&";
	}
}

std::string ProtoConverter::comparisonOpStr(BinaryOp::Op _op)
{
	switch (_op)
	{
	case BinaryOp::LT: return "<";
	case BinaryOp::GT: return ">";
	case BinaryOp::LTE: return "<=";
	case BinaryOp::GTE: return ">=";
	case BinaryOp::EQ: return "==";
	case BinaryOp::NEQ: return "!=";
	default: return "==";
	}
}

std::string ProtoConverter::logicalOpStr(BinaryOp::Op _op)
{
	switch (_op)
	{
	case BinaryOp::AND: return "&&";
	case BinaryOp::OR: return "||";
	default: return "&&";
	}
}

std::string ProtoConverter::paramTypeSolStr(ParamType _t)
{
	switch (_t)
	{
	case PARAM_BOOL: return "bool";
	case PARAM_ADDRESS: return "address";
	case PARAM_BYTES32: return "bytes32";
	default: return "uint256";
	}
}

std::string ProtoConverter::paramTypeAbiStr(ParamType _t)
{
	switch (_t)
	{
	case PARAM_BOOL: return "bool";
	case PARAM_ADDRESS: return "address";
	case PARAM_BYTES32: return "bytes32";
	default: return "uint256";
	}
}

std::string ProtoConverter::assignOpStr(AssignExpr::Op _op)
{
	switch (_op)
	{
	case AssignExpr::ASSIGN: return "=";
	case AssignExpr::ADD_ASSIGN: return "+=";
	case AssignExpr::SUB_ASSIGN: return "-=";
	case AssignExpr::MUL_ASSIGN: return "*=";
	case AssignExpr::DIV_ASSIGN: return "/=";
	case AssignExpr::MOD_ASSIGN: return "%=";
	case AssignExpr::AND_ASSIGN: return "&=";
	case AssignExpr::OR_ASSIGN: return "|=";
	case AssignExpr::XOR_ASSIGN: return "^=";
	case AssignExpr::SHL_ASSIGN: return "<<=";
	case AssignExpr::SHR_ASSIGN: return ">>=";
	default: return "=";
	}
}

std::string ProtoConverter::operatorSymbol(UsingForBinding::OperatorKind _k)
{
	switch (_k)
	{
	case UsingForBinding::OP_ADD:         return "+";
	case UsingForBinding::OP_SUB:         return "-";
	case UsingForBinding::OP_MUL:         return "*";
	case UsingForBinding::OP_DIV:         return "/";
	case UsingForBinding::OP_MOD:         return "%";
	case UsingForBinding::OP_EQ:          return "==";
	case UsingForBinding::OP_NEQ:         return "!=";
	case UsingForBinding::OP_LT:          return "<";
	case UsingForBinding::OP_GT:          return ">";
	case UsingForBinding::OP_LTE:         return "<=";
	case UsingForBinding::OP_GTE:         return ">=";
	case UsingForBinding::OP_BIT_AND:     return "&";
	case UsingForBinding::OP_BIT_OR:      return "|";
	case UsingForBinding::OP_BIT_XOR:     return "^";
	case UsingForBinding::OP_BIT_NOT:     return "~";
	case UsingForBinding::OP_UNARY_MINUS: return "-";
	case UsingForBinding::OP_NONE:        return "";
	}
	return "";
}

std::string ProtoConverter::emitUsingFor(UsingForDirective const& _d, bool _fileLevel)
{
	// Need at least one free function to name in the binding list, and at
	// least one binding. Everything else (invalid operator target, arity
	// mismatches, duplicate operator bindings) is INTENDED — do not filter.
	if (m_freeFunctions.empty() || _d.bindings_size() == 0)
		return {};

	// Target-type selector. `uint256` / `bytes32` / `address` / `bool` are
	// always available; `MyUint` only when the file declared the UDVT.
	static char const* const s_targets[] = {"uint256", "bytes32", "address", "bool"};
	unsigned tableSize = m_hasUdvt ? 5 : 4;
	unsigned pick = _d.target_type_idx() % tableSize;
	std::string targetType = (pick == 4) ? "MyUint" : s_targets[pick];

	std::ostringstream o;
	if (!_fileLevel)
		o << "\t";
	o << "using {";
	for (int i = 0; i < _d.bindings_size(); i++)
	{
		auto const& b = _d.bindings(i);
		if (i > 0)
			o << ", ";
		unsigned fidx = b.function_idx() % static_cast<unsigned>(m_freeFunctions.size());
		o << m_freeFunctions[fidx].name;
		UsingForBinding::OperatorKind kind = b.has_operator_kind()
			? b.operator_kind()
			: UsingForBinding::OP_NONE;
		if (kind != UsingForBinding::OP_NONE)
		{
			std::string sym = operatorSymbol(kind);
			if (!sym.empty())
				o << " as " << sym;
		}
	}
	o << "} for " << targetType;
	if (_fileLevel && _d.has_is_global() && _d.is_global())
		o << " global";
	o << ";\n";
	return o.str();
}
