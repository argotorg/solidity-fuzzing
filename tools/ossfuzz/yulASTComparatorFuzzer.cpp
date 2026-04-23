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
 * Proto fuzzer for the yuldiff AST comparator.
 *
 * Generates a Yul program P from protobuf, parses it, and runs two oracles:
 *
 * Oracle 1 — α-renaming invariance (completeness).
 *   Produces P' by consistently renaming every user-defined name in P to a fresh
 *   name (yd_0, yd_1, ...). Asserts the comparator reports EQUIVALENT. A failure
 *   here means the comparator over-reports mismatches on a program that really is
 *   α-equivalent to the original.
 *
 * Oracle 2 — structural sensitivity (soundness).
 *   Produces P'' by dropping the last statement of the root block. Asserts the
 *   comparator reports MISMATCH. A failure here means the comparator calls
 *   structurally different programs equivalent — i.e. the bimap trick is hiding
 *   real differences.
 *
 * Both oracles share one parse; cloning/mutation is done on the AST
 * (via ASTCopier) so nothing needs to re-parse. Sub-objects are shared by
 * reference — the comparator opens a fresh ScopeBimap::Scope per object,
 * so sub-objects effectively self-compare.
 */

#include <tools/ossfuzz/yulProto.pb.h>
#include <tools/ossfuzz/protoToYul.h>

#include <tools/yuldiff/ASTComparator.h>

#include <libyul/AST.h>
#include <libyul/Dialect.h>
#include <libyul/Object.h>
#include <libyul/ObjectParser.h>
#include <libyul/YulString.h>
#include <libyul/backends/evm/EVMDialect.h>
#include <libyul/optimiser/ASTCopier.h>

#include <liblangutil/CharStream.h>
#include <liblangutil/ErrorReporter.h>
#include <liblangutil/EVMVersion.h>
#include <liblangutil/Scanner.h>

#include <src/libfuzzer/libfuzzer_macro.h>

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <memory>
#include <string>

using namespace solidity;
using namespace solidity::yul;
using namespace solidity::langutil;

// Deliberately no `using namespace solidity::yul::test::yul_fuzzer` — that
// namespace defines a protobuf-generated `Object` class which would shadow
// `yul::Object` throughout this file.
using Program = solidity::yul::test::yul_fuzzer::Program;
using ProtoConverter = solidity::yul::test::yul_fuzzer::ProtoConverter;

namespace
{

/// ASTCopier that rewrites every user-defined YulName it sees with a fresh
/// one (yd_0, yd_1, ...), consistently within one AST. Builtins never hit
/// translateIdentifier (they flow through as BuiltinName), so we can rename
/// unconditionally — every name reaching this path is user-defined.
class AlphaRenamer: public ASTCopier
{
public:
	YulName translateIdentifier(YulName _name) override
	{
		auto [it, inserted] = m_map.try_emplace(_name, YulName());
		if (inserted)
			it->second = YulName("yd_" + std::to_string(m_counter++));
		return it->second;
	}
private:
	std::map<YulName, YulName> m_map;
	size_t m_counter = 0;
};

/// ASTCopier that flips the first numeric Literal it encounters in
/// Expression position. Case::value literals (Switch cases) are reached via
/// ASTCopier::translate(Literal), which is non-virtual — those are not
/// flipped, which is intentional: we only probe via the Expression-dispatch
/// path that ASTComparator likewise walks.
///
/// Flipping a single leaf forces ASTComparator to traverse every scope/
/// statement/expression path down to the `_a.value != _b.value` check —
/// a much stronger soundness probe than dropping a statement, which only
/// hits the top-level Block size check.
class LiteralFlipper: public ASTCopier
{
public:
	using ASTCopier::operator();

	Expression operator()(Literal const& _literal) override
	{
		if (m_flipped || _literal.kind != LiteralKind::Number)
			return ASTCopier::operator()(_literal);
		m_flipped = true;
		// XOR the low bit — every numeric literal is now guaranteed to
		// differ from its original, regardless of original value.
		u256 newVal = _literal.value.value() ^ u256(1);
		return Literal{_literal.debugData, _literal.kind, LiteralValue(newVal)};
	}

	bool flipped() const { return m_flipped; }

private:
	bool m_flipped = false;
};

std::shared_ptr<Object> parseYul(std::string const& _source, Dialect const& _dialect)
{
	ErrorList errors;
	ErrorReporter reporter(errors);
	auto charStream = std::make_shared<CharStream>(_source, "src");
	auto scanner = std::make_shared<Scanner>(*charStream);
	auto object = ObjectParser(reporter, _dialect).parse(scanner, false);
	if (!object || reporter.hasErrors())
		return nullptr;
	return object;
}

/// Build a new Object whose code is @a _newBlock, sharing everything else
/// (sub-objects, debug data, indices) with @a _template by reference.
std::shared_ptr<Object> rebuildObject(Object const& _template, Dialect const& _dialect, Block _newBlock)
{
	auto obj = std::make_shared<Object>();
	obj->name = _template.name;
	obj->setCode(std::make_shared<AST>(_dialect, std::move(_newBlock)));
	obj->subObjects = _template.subObjects;
	obj->subIndexByName = _template.subIndexByName;
	obj->subId = _template.subId;
	obj->debugData = _template.debugData;
	return obj;
}

void dumpOnFailure(char const* _tag, std::string const& _original, Object const& _variant, Dialect const& _dialect)
{
	std::cerr << "yul_ast_comparator_fuzz: oracle failure (" << _tag << ")\n";
	std::cerr << "--- original source ---\n" << _original << "\n";
	std::cerr << "--- variant (printed) ---\n"
		<< _variant.toString(DebugInfoSelection::None(), nullptr) << "\n";
	std::cerr.flush();
}

} // namespace

DEFINE_PROTO_FUZZER(Program const& _input)
{
	// filterStatefulInstructions=true: the comparator doesn't execute code, so
	// sstore/tstore/log have no value here and just bloat the AST.
	ProtoConverter converter(
		/* filterStatefulInstructions */ true,
		/* filterOptimizationNoise     */ true
	);
	std::string yulSource = converter.programToString(_input);

	if (char const* dumpPath = getenv("PROTO_FUZZER_DUMP_PATH"))
	{
		std::ofstream of(dumpPath);
		of.write(yulSource.data(), static_cast<std::streamsize>(yulSource.size()));
	}

	YulStringRepository::reset();
	Dialect const& dialect = EVMDialect::strictAssemblyForEVMObjects(EVMVersion::current(), std::nullopt);

	auto objA = parseYul(yulSource, dialect);
	if (!objA || !objA->hasCode())
		return;

	// -------- Oracle 1: α-renaming invariance --------
	{
		AlphaRenamer renamer;
		Block renamed = renamer.translate(objA->code()->root());
		auto objRenamed = rebuildObject(*objA, dialect, std::move(renamed));

		tools::cmpast::ASTComparator cmp(dialect);
		auto result = cmp.compareObjects(*objA, *objRenamed);
		if (!result)
		{
			auto const& mm = result.mismatch();
			std::cerr << "yul_ast_comparator_fuzz: oracle 1 (α-rename invariance) FAILED\n"
				<< "  at:     " << mm.path << "\n"
				<< "  reason: " << mm.reason << "\n";
			if (!mm.lhs.empty())
				std::cerr << "  lhs: " << mm.lhs << "\n  rhs: " << mm.rhs << "\n";
			dumpOnFailure("alpha-rename", yulSource, *objRenamed, dialect);
			std::abort();
		}
	}

	// -------- Oracle 2: structural-mutation sensitivity --------
	// Two mutation strategies:
	//   literal-flip (default, ~90%): flip one numeric literal. Equal-size
	//     variant, so ASTComparator has to walk all scopes/statements/
	//     expressions down to the `_a.value != _b.value` check — exercises
	//     far more of the comparator than a top-level size diff does.
	//   drop-mid-stmt (~10%, or fallback): drop the middle root-block
	//     statement. Only hits the Block size check, but keeps that path
	//     under regular coverage instead of leaving it to the rare
	//     no-literal case.
	// Mode is picked by hashing the Yul source so that a given crash input
	// always replays with the same mutation.
	{
		Block const& root = objA->code()->root();
		bool const forceDropStmt = (std::hash<std::string>{}(yulSource) % 10 == 0);

		Block mutated;
		char const* tag = nullptr;

		if (!forceDropStmt)
		{
			LiteralFlipper flipper;
			mutated = flipper.translate(root);
			if (flipper.flipped())
				tag = "literal-flip";
		}

		if (!tag)
		{
			// Either forced into drop-stmt mode, or literal-flip found no
			// Expression-position numeric literal (common for very small
			// programs).
			if (root.statements.empty())
				return; // Nothing to mutate.
			mutated = ASTCopier{}.translate(root);
			mutated.statements.erase(
				mutated.statements.begin()
				+ static_cast<ptrdiff_t>(mutated.statements.size() / 2)
			);
			tag = "drop-mid-stmt";
		}

		auto objMutated = rebuildObject(*objA, dialect, std::move(mutated));

		tools::cmpast::ASTComparator cmp(dialect);
		auto result = cmp.compareObjects(*objA, *objMutated);
		if (result)
		{
			std::cerr << "yul_ast_comparator_fuzz: oracle 2 (mutation sensitivity) FAILED\n"
				<< "  mutation: " << tag << "\n"
				<< "  a structurally-different program was reported as EQUIVALENT\n";
			dumpOnFailure(tag, yulSource, *objMutated, dialect);
			std::abort();
		}
	}
}
