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
/// Shared by the `stackshuffler` CLI and shuffler_proto_ossfuzz: the .stack format and an oracle for
/// stack::shuffle() that is independent of the shuffler's own helpers (replay, checkLayoutCompatibility).

#pragma once

#include <libyul/backends/evm/ssa/InstructionStore.h>
#include <libyul/backends/evm/ssa/SSACFGTypes.h>
#include <libyul/backends/evm/ssa/ShuffleTrace.h>
#include <libyul/backends/evm/ssa/StackSlot.h>
#include <libyul/backends/evm/ssa/spill/SpillSet.h>
#include <libyul/backends/evm/ssa/stack/Shuffler.h>
#include <libsolutil/StringUtils.h>

#include <range/v3/view/split.hpp>
#include <range/v3/view/transform.hpp>

#include <fmt/format.h>
#include <fmt/ranges.h>

#include <algorithm>
#include <cstddef>
#include <map>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace solidity::yul::ssa::shuffler_tool
{

/// A StackSlot only carries an InstId, so keep the user's tokens ("v172", "phi9") to render slots back with.
struct ParsedIdentifierTable
{
	InstructionStore store;
	std::map<std::string, InstId> tokenToId;
	std::map<InstId, std::string> idToToken;

	std::string render(StackSlot const& _slot) const
	{
		if (_slot.isValue())
			if (auto const it = idToToken.find(_slot.value()); it != idToToken.end())
				return it->second;
		return slotToString(_slot);
	}

	std::string render(StackData const& _stack, char const _open = '[', char const _close = ']') const
	{
		return fmt::format(
			"{}{}{}",
			_open,
			fmt::join(_stack | ranges::views::transform([this](StackSlot const& _s) { return render(_s); }), ", "),
			_close
		);
	}
};

inline std::string render(ParsedIdentifierTable const& _table, ShuffleOp const& _op)
{
	switch (_op.kind)
	{
	case ShuffleOp::Kind::Swap: return fmt::format("SWAP{}", _op.depth);
	case ShuffleOp::Kind::Dup: return fmt::format("DUP{}", _op.depth);
	case ShuffleOp::Kind::Pop: return "POP";
	case ShuffleOp::Kind::Push: return fmt::format("PUSH {}", _table.render(_op.slot));
	case ShuffleOp::Kind::Load: return fmt::format("LOAD {}", _table.render(_op.slot));
	case ShuffleOp::Kind::Store: return fmt::format("STORE {}", _table.render(_op.slot));
	}
	solidity::util::unreachable();
}

inline std::string_view trim(std::string_view s)
{
	s.remove_prefix(std::min(s.find_first_not_of(" \t\r\v\n"), s.size()));
	s.remove_suffix(std::min(s.size() - s.find_last_not_of(" \t\r\v\n") - 1, s.size()));
	return s;
}

/// Tokens: vN, phiN, litN, JUNK, ReturnLabel[N], FunctionCallReturnLabel[N]. Equal tokens give equal slots.
inline StackSlot parseSlot(ParsedIdentifierTable& _table, std::string_view _token)
{
	if (_token == "JUNK")
		return StackSlot::makeJunk();

	auto const bracketed = [&](std::string_view _prefix) -> std::optional<std::uint32_t> {
		if (!_token.starts_with(_prefix) || !_token.ends_with("]"))
			return std::nullopt;
		auto const inner = _token.substr(_prefix.size(), _token.size() - _prefix.size() - 1);
		if (auto const num = solidity::util::parseArithmetic<std::uint32_t>(inner))
			return *num;
		throw std::runtime_error(fmt::format("Couldn't parse token: {}", _token));
	};
	if (auto const n = bracketed("ReturnLabel["))
		return StackSlot::makeFunctionReturnLabel(*n);
	if (auto const n = bracketed("FunctionCallReturnLabel["))
		return StackSlot::makeFunctionCallReturnLabel(*n);

	auto const number = [&](std::size_t _prefixLen) {
		auto const num = solidity::util::parseArithmetic<std::uint32_t>(_token.substr(_prefixLen));
		if (!num)
			throw std::runtime_error(fmt::format("Couldn't parse token: {}", _token));
		return *num;
	};
	auto const allocate = [&]() -> InstId {
		if (_token.starts_with("phi"))
			return number(3), _table.store.appendPhi({0});
		if (_token.starts_with("lit"))
			return _table.store.appendLiteral({0}, u256(number(3))).first;
		if (_token.starts_with("v"))
			return number(1), _table.store.appendBuiltinCall({0}, {}, {});
		throw std::runtime_error(fmt::format("Unknown token: {}", _token));
	};

	std::string const token{_token};
	auto it = _table.tokenToId.find(token);
	if (it == _table.tokenToId.end())
	{
		it = _table.tokenToId.emplace(token, allocate()).first;
		_table.idToToken.emplace(it->second, token);
	}
	return StackSlot::makeValue(_table.store, it->second);
}

inline StackData parseSlots(ParsedIdentifierTable& _table, std::string_view _input, char const _open, char const _close)
{
	_input = trim(_input);
	if (!_input.starts_with(_open) || !_input.ends_with(_close))
		throw std::runtime_error(fmt::format("Expected {}...{}: {}", _open, _close, _input));
	_input = trim(_input.substr(1, _input.size() - 2));
	StackData result;
	if (_input.empty())
		return result;
	for (auto&& tokenRange: ranges::views::split(_input, ','))
	{
		std::string_view token;
		if (ranges::begin(tokenRange) != ranges::end(tokenRange))
			token = {&*ranges::begin(tokenRange), static_cast<std::size_t>(ranges::distance(tokenRange))};
		token = trim(token);
		if (token.empty())
			throw std::runtime_error("Empty token");
		result.push_back(parseSlot(_table, token));
	}
	return result;
}

/// One stack::shuffle() invocation. `.stack` format (`//` comments):
///   initial: [v1, phi2, lit3, JUNK]
///   target: [phi2, v1, JUNK, lit3]
///   spilled: {v1}
///   allowSpilling: true
///   reachableDepth: 16
struct ShuffleCase
{
	StackData initial;
	StackData target;
	StackData spilled;
	bool allowSpilling = true;
	std::size_t reachableDepth = reachableStackDepth;

	spill::SpillSet spillSet() const
	{
		spill::SpillSet spills;
		for (StackSlot const& slot: spilled)
			if (!spills.isSpilled(slot))
				spills.add(slot);
		return spills;
	}

	std::string format(ParsedIdentifierTable const& _table) const
	{
		return fmt::format(
			"initial: {}\ntarget: {}\nspilled: {}\nallowSpilling: {}\nreachableDepth: {}\n",
			_table.render(initial),
			_table.render(target),
			_table.render(spilled, '{', '}'),
			allowSpilling ? "true" : "false",
			reachableDepth
		);
	}

	static ShuffleCase parse(ParsedIdentifierTable& _table, std::string_view _source)
	{
		ShuffleCase result;
		bool haveInitial = false;
		bool haveTarget = false;
		for (auto&& lineRange: ranges::views::split(_source, '\n'))
		{
			if (ranges::begin(lineRange) == ranges::end(lineRange))
				continue;
			std::string_view line{&*ranges::begin(lineRange), static_cast<std::size_t>(ranges::distance(lineRange))};
			line = trim(line.substr(0, line.find("//")));
			auto const colon = line.find(':');
			if (line.empty() || colon == std::string_view::npos)
				continue;
			auto const key = trim(line.substr(0, colon));
			auto const value = trim(line.substr(colon + 1));
			if (key == "initial")
				result.initial = parseSlots(_table, value, '[', ']'), haveInitial = true;
			else if (key == "target")
				result.target = parseSlots(_table, value, '[', ']'), haveTarget = true;
			else if (key == "spilled")
				result.spilled = parseSlots(_table, value, '{', '}');
			else if (key == "allowSpilling")
			{
				if (value != "true" && value != "false")
					throw std::runtime_error(fmt::format("Couldn't parse allowSpilling: {}", value));
				result.allowSpilling = value == "true";
			}
			else if (key == "reachableDepth")
			{
				auto const n = solidity::util::parseArithmetic<std::size_t>(value);
				if (!n || *n < 2 || *n > reachableStackDepth)
					throw std::runtime_error(fmt::format("reachableDepth must be in [2, {}]: {}", reachableStackDepth, value));
				result.reachableDepth = *n;
			}
			else if (key == "targetStackTop" || key == "targetStackTailSet" || key == "targetStackSize")
				throw std::runtime_error(
					"Old .stack format (targetStackTop/TailSet/Size): the shuffler now takes a positional `target:`"
				);
			else
				throw std::runtime_error(fmt::format("Unknown key: {}", key));
		}
		if (!haveInitial || !haveTarget)
			throw std::runtime_error("Need both `initial:` and `target:`");
		for (StackSlot const& slot: result.spilled)
			if (!slot.isVariable())
				throw std::runtime_error(fmt::format("Only variables can be spilled: {}", _table.render(slot)));
		return result;
	}
};

/// Precondition of stack::shuffle(): every target slot is producible
inline bool targetProducible(ShuffleCase const& _case)
{
	spill::SpillSet const spills = _case.spillSet();
	return std::all_of(_case.target.begin(), _case.target.end(), [&](StackSlot const& _slot) {
		return canBeFreelyGenerated(_slot) || (_slot.isVariable() && spills.isSpilled(_slot)) ||
			std::find(_case.initial.begin(), _case.initial.end(), _slot) != _case.initial.end();
	});
}

/// Checks a shuffle result against the spec; returns the violations (empty = ok)
inline std::vector<std::string> checkShuffle(
	ParsedIdentifierTable const& _table,
	ShuffleCase const& _case,
	stack::ShuffleResult const& _result,
	StackData const& _shuffled,
	spill::SpillSet const& _spillsAfter
)
{
	std::vector<std::string> errors;
	bool const hasReturnLabel = std::any_of(
		_case.initial.begin(), _case.initial.end(), [](StackSlot const& _s) { return _s.isFunctionReturnLabel(); }
	);
	if (_result.status != stack::ShuffleResult::Status::Admissible)
	{
		// With spilling there is always a way out, except for a return label, which can be neither spilled nor duplicated.
		if (_case.allowSpilling && !hasReturnLabel)
			errors.emplace_back("StackTooDeep although spilling is allowed and there is no return label");
		return errors;
	}

	spill::SpillSet const spillsBefore = _case.spillSet();
	for (StackSlot const& slot: spillsBefore.spilledValues())
		if (!_spillsAfter.isSpilled(slot))
			errors.emplace_back(fmt::format("previously spilled {} is no longer spilled", _table.render(slot)));
	if (!_case.allowSpilling && _spillsAfter.numSpilled() != spillsBefore.numSpilled())
		errors.emplace_back("added spills although spilling was disallowed");

	StackData s = _case.initial;
	for (std::size_t index = 0; index < _result.trace.size(); ++index)
	{
		ShuffleOp const& op = _result.trace[index];
		auto const fail = [&](std::string const& _what) {
			errors.emplace_back(fmt::format("op #{} {}: {} on {}", index, render(_table, op), _what, _table.render(s)));
		};
		std::size_t const depth = op.depth;
		switch (op.kind)
		{
		case ShuffleOp::Kind::Swap:
			if (depth < 1 || depth > _case.reachableDepth || depth >= s.size())
				return fail("depth out of range"), errors;
			std::swap(s[s.size() - 1 - depth], s.back());
			break;
		case ShuffleOp::Kind::Dup:
			if (depth < 1 || depth > _case.reachableDepth || depth > s.size())
				return fail("depth out of range"), errors;
			s.push_back(s[s.size() - depth]);
			break;
		case ShuffleOp::Kind::Push:
			if (!canBeFreelyGenerated(op.slot))
				return fail("slot is not freely generatable"), errors;
			s.push_back(op.slot);
			break;
		case ShuffleOp::Kind::Load:
			if (!op.slot.isVariable() || !_spillsAfter.isSpilled(op.slot))
				return fail("slot is not spilled"), errors;
			s.push_back(op.slot);
			break;
		case ShuffleOp::Kind::Store:
			if (s.empty() || s.back() != op.slot || !_spillsAfter.isSpilled(op.slot))
				return fail("top is not the spilled slot"), errors;
			s.pop_back();
			break;
		case ShuffleOp::Kind::Pop:
			if (s.empty())
				return fail("empty stack"), errors;
			s.pop_back();
			break;
		}
		if (s.size() > 1024)
			return fail("stack overflow"), errors;
	}
	if (s != _shuffled)
		errors.emplace_back(fmt::format("replay gives {}, shuffler reports {}", _table.render(s), _table.render(_shuffled)));

	if (_shuffled.size() != _case.target.size())
		errors.emplace_back(fmt::format("final size {} != target size {}", _shuffled.size(), _case.target.size()));
	else
		for (std::size_t i = 0; i < _shuffled.size(); ++i)
			if (!_case.target[i].isJunk() && _shuffled[i] != _case.target[i])
				errors.emplace_back(fmt::format(
					"offset {}: have {}, target wants {}", i, _table.render(_shuffled[i]), _table.render(_case.target[i])
				));

	if (_result.sourceOf.size() != _case.target.size())
		errors.emplace_back(fmt::format("sourceOf has {} entries for {} targets", _result.sourceOf.size(), _case.target.size()));
	else
		for (std::size_t i = 0; i < _result.sourceOf.size(); ++i)
			if (auto const src = _result.sourceOf[i])
			{
				if (src->value >= _case.initial.size())
					errors.emplace_back(fmt::format("sourceOf[{}] = {} is past the initial stack", i, src->value));
				else if (!_case.target[i].isJunk() && _case.initial[src->value] != _case.target[i])
					errors.emplace_back(fmt::format(
						"sourceOf[{}] serves {} from {}", i, _table.render(_case.target[i]), _table.render(_case.initial[src->value])
					));
			}
	return errors;
}

/// One row per operation (stack after it), then the target; `*` is junk
inline void printTrace(std::ostream& _out, ParsedIdentifierTable const& _table, ShuffleCase const& _case, ShuffleTrace const& _trace)
{
	std::vector<std::pair<std::string, StackData>> rows{{"(initial)", _case.initial}};
	StackData s = _case.initial;
	for (ShuffleOp const& op: _trace)
	{
		apply(s, op);
		rows.emplace_back(render(_table, op), s);
	}
	rows.emplace_back("(target)", _case.target);

	auto const cell = [&](StackSlot const& _slot) { return _slot.isJunk() ? std::string("*") : _table.render(_slot); };
	std::size_t columns = 0;
	std::size_t opWidth = 0;
	for (auto const& [op, stack]: rows)
		columns = std::max(columns, stack.size()), opWidth = std::max(opWidth, op.size());
	std::vector<std::size_t> widths(columns, 3);
	for (auto const& [op, stack]: rows)
		for (std::size_t i = 0; i < stack.size(); ++i)
			widths[i] = std::max(widths[i], cell(stack[i]).size());

	auto const line = [&](std::string const& _op, StackData const& _stack) {
		_out << fmt::format("{:>{}} |", _op, opWidth);
		for (std::size_t i = 0; i < _stack.size(); ++i)
			_out << fmt::format(" {:>{}}", cell(_stack[i]), widths[i]);
		_out << '\n';
	};
	_out << fmt::format("{:>{}} |", "", opWidth);
	for (std::size_t i = 0; i < columns; ++i)
		_out << fmt::format(" {:>{}}", i, widths[i]);
	_out << '\n';
	for (std::size_t i = 0; i < rows.size(); ++i)
	{
		if (i == rows.size() - 1)
			_out << std::string(opWidth + 1, '-') << "+\n";
		line(rows[i].first, rows[i].second);
	}
}

}
