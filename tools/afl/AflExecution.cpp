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

#include <tools/afl/AflExecution.h>

#include <tools/ossfuzz/SolidityEvmoneInterface.h>

#include <libsolidity/ast/ASTVisitor.h>
#include <libsolidity/ast/CallGraph.h>
#include <libsolidity/interface/CompilerStack.h>
#include <libsolutil/Keccak256.h>

#include <algorithm>
#include <limits>
#include <random>
#include <cctype>
#include <sstream>
#include <string_view>

using namespace solidity;
using namespace solidity::util;
using namespace solidity::test;
using namespace solidity::test::fuzzer;
using namespace solidity::test::fuzzer::afl;

namespace
{

constexpr std::size_t maxScriptCalls = 32;
constexpr std::size_t maxGeneratedFunctions = 16;
constexpr std::size_t maxEncodedArgBytes = 4096;

std::string_view trim(std::string_view _s)
{
	while (!_s.empty() && std::isspace(static_cast<unsigned char>(_s.front())))
		_s.remove_prefix(1);
	while (!_s.empty() && std::isspace(static_cast<unsigned char>(_s.back())))
		_s.remove_suffix(1);
	return _s;
}

/// Splits at top-level commas, respecting (), [] and "..."
std::vector<std::string_view> splitTopLevel(std::string_view _s)
{
	std::vector<std::string_view> parts;
	int depth = 0;
	bool inString = false;
	std::size_t start = 0;
	for (std::size_t i = 0; i < _s.size(); ++i)
	{
		char const c = _s[i];
		if (inString)
		{
			if (c == '\\')
				++i;
			else if (c == '"')
				inString = false;
			continue;
		}
		if (c == '"')
			inString = true;
		else if (c == '(' || c == '[')
			++depth;
		else if (c == ')' || c == ']')
			--depth;
		else if (c == ',' && depth == 0)
		{
			parts.push_back(trim(_s.substr(start, i - start)));
			start = i + 1;
		}
	}
	if (!trim(_s.substr(start)).empty() || !parts.empty())
		parts.push_back(trim(_s.substr(start)));
	return parts;
}

bytes selectorOf(std::string const& _signature)
{
	bytes const hash = keccak256(_signature).asBytes();
	return bytes(hash.begin(), hash.begin() + 4);
}

bytes word(u256 const& _value)
{
	return toBigEndian(_value);
}

bytes leftAligned(bytes _data)
{
	_data.resize((_data.size() + 31) / 32 * 32, 0);
	if (_data.empty())
		_data.resize(32, 0);
	return _data;
}

std::optional<u256> parseNumber(std::string_view _token)
{
	bool negative = false;
	if (!_token.empty() && _token.front() == '-')
		negative = true, _token.remove_prefix(1);
	std::string digits;
	for (char c: _token)
		if (c != '_')
			digits += c;
	if (digits.empty())
		return std::nullopt;
	try
	{
		bool const hex = digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X');
		if (hex ? digits.size() > 66 : !std::all_of(digits.begin(), digits.end(), ::isdigit))
			return std::nullopt;
		bigint const v(digits);
		if (v >= bigint(1) << 256)
			return std::nullopt;
		return negative && v != 0 ? u256((bigint(1) << 256) - v) : u256(v);
	}
	catch (...)
	{
		return std::nullopt;
	}
}

std::optional<bytes> parseStringLiteral(std::string_view _token)
{
	if (_token.size() < 2 || _token.front() != '"' || _token.back() != '"')
		return std::nullopt;
	bytes out;
	for (std::size_t i = 1; i + 1 < _token.size(); ++i)
	{
		char c = _token[i];
		if (c == '\\' && i + 2 < _token.size())
		{
			char const e = _token[++i];
			c = e == 'n' ? '\n' : e == 't' ? '\t' : e == '0' ? '\0' : e;
		}
		out.push_back(static_cast<uint8_t>(c));
	}
	return out;
}

/// One isoltest argument as ABI words (isoltest arguments are literal words, not typed values)
std::optional<bytes> encodeScriptArg(std::string_view _token)
{
	if (_token == "true")
		return word(1);
	if (_token == "false")
		return word(0);
	if (_token.starts_with("hex\""))
	{
		auto const s = parseStringLiteral(_token.substr(3));
		if (!s || s->size() % 2)
			return std::nullopt;
		try
		{
			return leftAligned(fromHex(std::string(s->begin(), s->end())));
		}
		catch (...)
		{
			return std::nullopt;
		}
	}
	if (_token.starts_with("\""))
	{
		auto const s = parseStringLiteral(_token);
		return s ? std::optional<bytes>(leftAligned(*s)) : std::nullopt;
	}
	for (std::string_view const align: {"left(", "right("})
		if (_token.starts_with(align) && _token.ends_with(")"))
		{
			auto const inner = encodeScriptArg(trim(_token.substr(align.size(), _token.size() - align.size() - 1)));
			if (!inner || align == "right(")
				return inner;
			// left(): the value's significant bytes moved to the front of the word
			bytes const& w = *inner;
			auto const first = std::find_if(w.begin(), w.end(), [](uint8_t b) { return b != 0; });
			bytes out(first, w.end());
			return leftAligned(out);
		}
	if (auto const n = parseNumber(_token))
		return word(*n);
	return std::nullopt;
}

std::optional<u256> parseValue(std::string_view _s)
{
	_s = trim(_s);
	auto const space = _s.find(' ');
	if (space == std::string_view::npos)
		return std::nullopt;
	auto const amount = parseNumber(trim(_s.substr(0, space)));
	auto const unit = trim(_s.substr(space + 1));
	if (!amount)
		return std::nullopt;
	if (unit == "wei")
		return *amount;
	if (unit == "gwei")
		return *amount * u256(1000000000);
	if (unit == "ether")
		return *amount * u256("1000000000000000000");
	return std::nullopt;
}

struct ScriptCall
{
	std::string signature;
	bytes args;
	u256 value;
};

/// `sig[, N unit]: args -> expected`; expectations are ignored (the oracle is differential)
std::vector<ScriptCall> parseScript(std::string const& _source)
{
	std::vector<ScriptCall> calls;
	auto const marker = _source.find("// ----");
	if (marker == std::string::npos)
		return calls;
	std::istringstream lines(_source.substr(marker + 7));
	std::string raw;
	while (std::getline(lines, raw) && calls.size() < maxScriptCalls)
	{
		std::string_view line = trim(raw);
		if (!line.starts_with("//"))
			continue;
		line = trim(line.substr(2));
		if (line.empty() || !(std::isalpha(static_cast<unsigned char>(line[0])) || line[0] == '_'))
			continue;
		auto const open = line.find('(');
		if (open == std::string_view::npos)
			continue;
		int depth = 0;
		std::size_t close = open;
		for (; close < line.size(); ++close)
		{
			depth += line[close] == '(' ? 1 : line[close] == ')' ? -1 : 0;
			if (depth == 0)
				break;
		}
		if (close == line.size())
			continue;
		ScriptCall call{std::string(line.substr(0, close + 1)), {}, 0};
		std::string_view rest = line.substr(close + 1);
		std::string_view const head = trim(rest.substr(0, rest.find("->")));
		std::string_view argText;
		auto const colon = head.find(':');
		std::string_view const valueText = trim(head.substr(0, colon));
		if (colon != std::string_view::npos)
			argText = trim(head.substr(colon + 1));
		if (valueText.starts_with(","))
		{
			auto const v = parseValue(valueText.substr(1));
			if (!v)
				continue;
			call.value = *v;
		}
		else if (!valueText.empty())
			continue;
		bool ok = true;
		for (std::string_view arg: splitTopLevel(argText))
			if (auto const encoded = encodeScriptArg(arg))
				call.args += *encoded;
			else
				ok = false;
		if (ok)
			calls.push_back(std::move(call));
	}
	return calls;
}

class Entropy
{
public:
	explicit Entropy(bytes const& _data): m_data(_data) {}
	/// Past the end, a keccak chain over the data: three call passes otherwise run out and pass all-zero arguments
	uint8_t byte()
	{
		if (m_pos < m_data.size())
			return m_data[m_pos++];
		if (m_extensionPos == m_extension.size())
		{
			m_chain = keccak256(m_extension.empty() ? m_data : m_chain.asBytes());
			m_extension = m_chain.asBytes();
			m_extensionPos = 0;
		}
		return m_extension[m_extensionPos++];
	}
	bytes take(std::size_t _n)
	{
		bytes out;
		for (std::size_t i = 0; i < _n; ++i)
			out.push_back(byte());
		return out;
	}
private:
	bytes const& m_data;
	std::size_t m_pos = 0;
	h256 m_chain;
	bytes m_extension;
	std::size_t m_extensionPos = 0;
};

struct AbiType
{
	enum class Kind { Uint, Int, Address, Bool, FixedBytes, Bytes, String, Array, Tuple };
	Kind kind;
	unsigned size = 0; ///< bits for Uint/Int, bytes for FixedBytes, length for a static Array (0 = dynamic)
	std::vector<AbiType> members; ///< element type for Array, components for Tuple

	bool isDynamic() const
	{
		switch (kind)
		{
		case Kind::Bytes:
		case Kind::String:
			return true;
		case Kind::Array:
			return size == 0 || members[0].isDynamic();
		case Kind::Tuple:
			return std::any_of(members.begin(), members.end(), [](AbiType const& _t) { return _t.isDynamic(); });
		default:
			return false;
		}
	}
};

std::optional<AbiType> parseType(std::string_view _s)
{
	_s = trim(_s);
	if (_s.ends_with("]"))
	{
		auto const open = _s.rfind('[');
		if (open == std::string_view::npos)
			return std::nullopt;
		auto element = parseType(_s.substr(0, open));
		if (!element)
			return std::nullopt;
		std::string_view const len = _s.substr(open + 1, _s.size() - open - 2);
		unsigned size = 0;
		if (!len.empty())
		{
			auto const n = parseNumber(len);
			if (!n || *n == 0 || *n > 64)
				return std::nullopt;
			size = static_cast<unsigned>(*n);
		}
		return AbiType{AbiType::Kind::Array, size, {std::move(*element)}};
	}
	if (_s.starts_with("(") && _s.ends_with(")"))
	{
		AbiType tuple{AbiType::Kind::Tuple, 0, {}};
		for (std::string_view member: splitTopLevel(_s.substr(1, _s.size() - 2)))
			if (auto t = parseType(member))
				tuple.members.push_back(std::move(*t));
			else
				return std::nullopt;
		return tuple;
	}
	auto const bits = [&](std::size_t _prefix, unsigned _default) -> std::optional<unsigned> {
		if (_s.size() == _prefix)
			return _default;
		auto const n = parseNumber(_s.substr(_prefix));
		return n ? std::optional<unsigned>(static_cast<unsigned>(*n)) : std::nullopt;
	};
	if (_s == "address")
		return AbiType{AbiType::Kind::Address};
	if (_s == "bool")
		return AbiType{AbiType::Kind::Bool};
	if (_s == "string")
		return AbiType{AbiType::Kind::String};
	if (_s == "bytes")
		return AbiType{AbiType::Kind::Bytes};
	if (_s.starts_with("bytes"))
		if (auto const n = bits(5, 0); n && *n >= 1 && *n <= 32)
			return AbiType{AbiType::Kind::FixedBytes, *n};
	if (_s.starts_with("uint"))
		if (auto const n = bits(4, 256); n && *n >= 8 && *n <= 256)
			return AbiType{AbiType::Kind::Uint, *n};
	if (_s.starts_with("int"))
		if (auto const n = bits(3, 256); n && *n >= 8 && *n <= 256)
			return AbiType{AbiType::Kind::Int, *n};
	// fixed/ufixed and anything else: not generated
	return std::nullopt;
}

/// Boundary-biased valid values, so the decoder accepts them and the function body runs
u256 integer(Entropy& _e, unsigned _bits, bool _signed)
{
	bigint const range = bigint(1) << _bits;
	bigint const maxU = range - 1;
	bigint const maxS = (bigint(1) << (_bits - 1)) - 1;
	bigint v;
	switch (_e.byte() % 8)
	{
	case 0: v = 0; break;
	case 1: v = 1; break;
	case 2: v = _signed ? maxS : maxU; break;
	case 3: v = _signed ? bigint(-maxS - 1) : bigint(2); break;
	case 4: v = _e.byte() % 32; break;
	case 5: v = _signed ? bigint(-1) : maxU - 1; break;
	case 6: v = bigint(1) << (_e.byte() % _bits); break;
	default:
	{
		bigint r = 0;
		for (uint8_t b: _e.take(32))
			r = (r << 8) | b;
		v = r % range;
		if (_signed && v > maxS)
			v -= range;
	}
	}
	return v < 0 ? u256((bigint(1) << 256) + v) : u256(v);
}

bytes encodeValue(AbiType const& _type, Entropy& _e);

std::size_t staticSize(AbiType const& _type)
{
	switch (_type.kind)
	{
	case AbiType::Kind::Array: return _type.size * staticSize(_type.members[0]);
	case AbiType::Kind::Tuple:
	{
		std::size_t total = 0;
		for (AbiType const& m: _type.members)
			total += staticSize(m);
		return total;
	}
	default: return 32;
	}
}

bytes encodeSequence(std::vector<AbiType> const& _types, Entropy& _e)
{
	std::vector<bytes> heads;
	std::vector<bytes> tails;
	std::size_t headSize = 0;
	for (AbiType const& t: _types)
		headSize += t.isDynamic() ? 32 : staticSize(t);
	if (headSize > maxEncodedArgBytes)
		throw std::length_error("encoding too large");
	std::size_t tailOffset = headSize;
	for (AbiType const& t: _types)
	{
		bytes encoded = encodeValue(t, _e);
		if (t.isDynamic())
		{
			heads.push_back(word(tailOffset));
			tailOffset += encoded.size();
			tails.push_back(std::move(encoded));
		}
		else
			heads.push_back(std::move(encoded));
		if (tailOffset > maxEncodedArgBytes)
			throw std::length_error("encoding too large");
	}
	bytes out;
	for (bytes const& h: heads)
		out += h;
	for (bytes const& t: tails)
		out += t;
	return out;
}

bytes encodeValue(AbiType const& _type, Entropy& _e)
{
	switch (_type.kind)
	{
	case AbiType::Kind::Uint: return word(integer(_e, _type.size, false));
	case AbiType::Kind::Int: return word(integer(_e, _type.size, true));
	// The sender, often required to be nonzero or the owner, is EVMHost's tx_origin
	case AbiType::Kind::Address: return word(_e.byte() % 4 == 0 ? u256("0x9292929292929292929292929292929292929292") : integer(_e, 160, false));
	case AbiType::Kind::Bool: return word(_e.byte() & 1);
	case AbiType::Kind::FixedBytes:
	{
		bytes b = _e.take(_type.size);
		b.resize(32, 0);
		return b;
	}
	case AbiType::Kind::Bytes:
	case AbiType::Kind::String:
	{
		std::size_t const length = _e.byte() % 4 == 0 ? 0 : _e.byte() % 70;
		bytes out = word(length);
		if (length)
			out += leftAligned(_e.take(length));
		return out;
	}
	case AbiType::Kind::Array:
	{
		std::size_t const length = _type.size ? _type.size : _e.byte() % 4;
		std::vector<AbiType> const elements(length, _type.members[0]);
		bytes const body = encodeSequence(elements, _e);
		return _type.size ? body : word(length) + body;
	}
	case AbiType::Kind::Tuple:
		return encodeSequence(_type.members, _e);
	}
	solidity::util::unreachable();
}

/// Malformed variants of a valid encoding: what a decoder must reject (or clean), and where legacy and IR
/// have disagreed before (non-canonical bool, dirty high bits, negative/huge/backward tail offsets)
bytes corrupt(bytes _args, Entropy& _e)
{
	std::size_t const words = _args.size() / 32;
	if (words == 0)
		return _args;
	std::size_t const n = 1 + _e.byte() % 2;
	for (std::size_t k = 0; k < n; ++k)
	{
		std::size_t const at = (_e.byte() % words) * 32;
		u256 const original = fromBigEndian<u256>(bytesConstRef(_args.data() + at, 32));
		u256 replacement;
		switch (_e.byte() % 7)
		{
		case 0: replacement = original | (u256(1) << 255); break;
		case 1: replacement = 2; break;
		case 2: replacement = original | (u256(1) << (8 + _e.byte() % 240)); break;
		case 3: replacement = u256(0) - 32; break;
		case 4: replacement = u256(_args.size()) + 32 * (_e.byte() % 4); break;
		case 5: replacement = 0; break;
		default: replacement = u256(1) << 64; break;
		}
		bytes const w = word(replacement);
		std::copy(w.begin(), w.end(), _args.begin() + static_cast<std::ptrdiff_t>(at));
	}
	return _args;
}

std::optional<bytes> encodeArgs(std::string const& _signature, Entropy& _e)
{
	auto const open = _signature.find('(');
	if (open == std::string::npos || _signature.back() != ')')
		return std::nullopt;
	std::vector<AbiType> types;
	for (std::string_view param: splitTopLevel(std::string_view(_signature).substr(open + 1, _signature.size() - open - 2)))
		if (auto t = parseType(param))
			types.push_back(std::move(*t));
		else
			return std::nullopt;
	try
	{
		return encodeSequence(types, _e);
	}
	catch (std::length_error const&)
	{
		return std::nullopt;
	}
}

}

AflInput afl::splitInput(std::string_view _input)
{
	if (_input.size() >= 4 &&
		static_cast<unsigned char>(_input[_input.size() - 2]) == 0xCA &&
		static_cast<unsigned char>(_input[_input.size() - 1]) == 0xFE)
	{
		std::size_t const srcLen =
			static_cast<unsigned char>(_input[_input.size() - 4]) |
			(static_cast<std::size_t>(static_cast<unsigned char>(_input[_input.size() - 3])) << 8);
		if (srcLen <= _input.size() - 4)
		{
			bytes calldata(_input.begin() + static_cast<std::ptrdiff_t>(srcLen), _input.end() - 4);
			return {std::string(_input.substr(0, srcLen)), calldata, calldata};
		}
	}
	bytes entropy;
	h256 h = keccak256(std::string(_input));
	for (int i = 0; i < 8; ++i, h = keccak256(h.asBytes()))
		entropy += h.asBytes();
	return {std::string(_input), std::move(entropy), std::nullopt};
}

namespace
{
/// Version pragmas only gate compilation: real-world code pins versions this solc does not satisfy
std::string withoutVersionPragmas(std::string _source)
{
	static std::string const pragma = "pragma solidity";
	for (std::size_t pos = _source.find(pragma); pos != std::string::npos; pos = _source.find(pragma, pos))
	{
		std::size_t const end = _source.find(';', pos);
		if (end == std::string::npos)
			break;
		for (std::size_t i = pos; i <= end; ++i)
			if (_source[i] != '\n')
				_source[i] = ' ';
	}
	return _source;
}
}

std::optional<StringMap> afl::sourceUnits(std::string const& _source)
{
	std::optional<StringMap> units = sourceUnitsVerbatim(_source);
	if (units)
		for (auto& [_, source]: *units)
			source = withoutVersionPragmas(std::move(source));
	return units;
}

std::optional<StringMap> afl::sourceUnitsVerbatim(std::string const& _source)
{
	static std::string const marker = "==== Source:";
	if (_source.find("==== ExternalSource:") != std::string::npos)
		return std::nullopt;
	if (_source.find(marker) == std::string::npos)
		return StringMap{{"test.sol", _source}};
	StringMap units;
	std::string name = "test.sol";
	std::string current;
	std::istringstream lines(_source);
	std::string line;
	while (std::getline(lines, line))
	{
		if (line.starts_with(marker))
		{
			if (!current.empty() || units.empty())
				units[name] += current;
			current.clear();
			auto const end = line.rfind("====");
			name = std::string(trim(std::string_view(line).substr(marker.size(), end - marker.size())));
			if (name.empty())
				return std::nullopt;
			continue;
		}
		current += line + "\n";
	}
	units[name] += current;
	return units;
}

ContractInterface afl::interfaceOf(CompilerOutput const& _output)
{
	return {_output.methodIdentifiersInContract, _output.constructorSignature, _output.constructorPayable,
		_output.payableFunctions, _output.hasReceive, _output.hasFallback, _output.fallbackPayable};
}

CallPlan afl::planCalls(AflInput const& _input, ContractInterface const& _interface)
{
	CallPlan plan;
	bool scriptedConstructor = false;
	for (ScriptCall& call: parseScript(_input.source))
		if (call.signature == "constructor()")
		{
			plan.constructorArgs = std::move(call.args), plan.constructorValue = call.value;
			scriptedConstructor = true;
		}
		else
			plan.calls.push_back({call.signature, selectorOf(call.signature) + call.args, call.value});

	Entropy entropy(_input.entropy);
	if (!scriptedConstructor)
	{
		if (!_interface.constructorSignature.empty())
			if (auto args = encodeArgs(_interface.constructorSignature, entropy))
				plan.constructorArgs = std::move(*args);
		if (_interface.constructorPayable)
			plan.constructorValue = entropy.byte();
	}

	std::vector<std::string> signatures;
	if (_interface.methodIdentifiers.is_object())
		for (auto const& [signature, _]: _interface.methodIdentifiers.items())
			if (signatures.size() < maxGeneratedFunctions)
				signatures.push_back(signature);
	auto value = [&](std::string const& _signature) -> u256 {
		return _interface.payableFunctions.contains(_signature) ? u256(entropy.byte()) : u256(0);
	};
	for (std::string const& signature: signatures)
		if (auto args = encodeArgs(signature, entropy))
		{
			plan.calls.push_back({signature, selectorOf(signature) + *args, value(signature)});
			if (entropy.byte() % 2)
				plan.calls.push_back({signature + " [malformed]", selectorOf(signature) + corrupt(*args, entropy), 0});
		}
	// More passes in input-chosen orders with fresh arguments, so functions also see state that others wrote.
	// Executing is ~1000x cheaper than compiling, so these cost next to nothing.
	for (int pass = 0; pass < 2; ++pass)
	{
		for (std::size_t i = signatures.size(); i > 1; --i)
			std::swap(signatures[i - 1], signatures[entropy.byte() % i]);
		for (std::string const& signature: signatures)
			if (auto args = encodeArgs(signature, entropy))
				plan.calls.push_back({signature + " [again]", selectorOf(signature) + *args, value(signature)});
	}
	if (_interface.hasReceive || _interface.hasFallback)
		plan.calls.push_back({"<empty calldata>", {}, (_interface.hasReceive || _interface.fallbackPayable) ? u256(1 + entropy.byte()) : u256(0)});
	if (_interface.hasFallback)
		plan.calls.push_back({"<fallback>", bytes{0xff, 0xff, 0xff, 0xff} + entropy.take(entropy.byte() % 70), _interface.fallbackPayable ? u256(entropy.byte()) : u256(0)});
	if (_input.rawCalldata)
		plan.calls.push_back({"<raw calldata>", *_input.rawCalldata, 0});
	return plan;
}

Execution afl::execute(EVMHost& _host, bytes const& _bytecode, CallPlan const& _plan)
{
	Execution out;
	evmc::address const sender = _host.tx_context.tx_origin;
	_host.accounts[sender].set_balance(std::numeric_limits<uint64_t>::max());

	bytes const initCode = _bytecode + _plan.constructorArgs;
	evmc_message create = EvmoneUtility::initializeMessage(initCode, deployGas);
	create.kind = EVMC_CREATE;
	create.sender = sender;
	create.value = EVMHost::convertToEVMC(h256(_plan.constructorValue));
	_host.m_subCalls.clear();
	evmc::Result created = _host.call(create);
	out.deployStatus = created.status_code;
	out.deploySubCalls = std::move(_host.m_subCalls);
	_host.m_subCalls.clear();
	if (created.status_code != EVMC_SUCCESS)
		return out;
	evmc::address const contract = created.create_address;

	for (PlannedCall const& planned: _plan.calls)
	{
		_host.newTransaction();
		_host.m_subCallOutOfGas = false;
		_host.m_subCalls.clear();
		evmc_message msg = EvmoneUtility::initializeMessage(planned.calldata, callGas);
		msg.kind = EVMC_CALL;
		msg.sender = sender;
		msg.recipient = contract;
		msg.code_address = contract;
		msg.value = EVMHost::convertToEVMC(h256(planned.value));
		evmc::Result result = _host.call(msg);

		CallObservation observation{result.status_code, bytes(result.output_data, result.output_data + result.output_size),
			_host.m_subCallOutOfGas, {}, std::move(_host.m_subCalls)};
		_host.m_subCalls.clear();
		for (auto const& [address, account]: _host.accounts)
			if (!account.transient_storage.empty())
				observation.transientStorage[address] = account.transient_storage;
		if (result.status_code == EVMC_SUCCESS)
		{
			observation.storage.emplace();
			for (auto const& [address, account]: _host.accounts)
				if (!account.storage.empty())
					(*observation.storage)[address] = account.storage;
		}
		out.calls.push_back(std::move(observation));
		if (result.status_code == EVMC_OUT_OF_GAS || _host.m_subCallOutOfGas)
			break;
	}

	out.readsDeployedCode = _host.m_readsDeployedCode;
	out.state.result = std::move(created);
	out.state.logs.assign(_host.recorded_logs.begin(), _host.recorded_logs.end());
	for (auto const& [address, account]: _host.accounts)
	{
		if (!account.storage.empty())
			out.state.storage[address] = account.storage;
		if (!account.code.empty())
			out.state.accountCodeHashes[address] = keccak256(bytes(account.code.begin(), account.code.end()));
	}
	out.state.contractCreationOrder = _host.m_contractCreationOrder;
	for (auto const& [address, account]: _host.accounts)
		out.balances[address] = account.balance;
	return out;
}

namespace
{
/// Order-insensitive: legacy and IR evaluate some expressions (e.g. function call arguments) in different orders
std::vector<std::string> normalizedSubCalls(
	std::vector<EVMHost::SubCall> const& _calls,
	std::vector<evmc::address> const& _creationOrder
)
{
	std::vector<std::string> out;
	for (EVMHost::SubCall const& call: _calls)
	{
		// Precompiles: legacy codegen may copy memory through the identity precompile
		if (std::all_of(call.recipient.bytes, call.recipient.bytes + 18, [](uint8_t _b) { return _b == 0; }))
			continue;
		bool const creation = call.kind == EVMC_CREATE || call.kind == EVMC_CREATE2;
		std::string key = std::to_string(call.kind) + ":" + std::to_string(call.depth) + ":" +
			toHex(EVMHost::convertFromEVMC(call.value).asBytes()) + ":";
		// The init code of a creation differs by config; the created address is matched by creation order
		if (creation)
			key += toHex(EVMHost::convertFromEVMC(call.salt).asBytes());
		else
		{
			bytes const recipient(call.recipient.bytes, call.recipient.bytes + 20);
			key += toHex(normalizeCreatedAddresses(recipient.data(), recipient.size(), _creationOrder)) + ":" +
				toHex(normalizeCreatedAddresses(call.input.data(), call.input.size(), _creationOrder));
		}
		out.push_back(std::move(key));
	}
	std::sort(out.begin(), out.end());
	return out;
}
}

Comparison afl::compare(Execution const& _a, Execution const& _b)
{
	Comparison out;
	if (_a.readsDeployedCode || _b.readsDeployedCode)
		return out.skipped = "contract read deployed bytecode", out;
	if (_a.deployStatus == EVMC_OUT_OF_GAS || _b.deployStatus == EVMC_OUT_OF_GAS)
		return out.skipped = "deploy out of gas", out;
	if (_a.deployStatus != _b.deployStatus)
		return out.differences.push_back("deploy status differs"), out;
	if (_a.deployStatus != EVMC_SUCCESS)
		return out;

	auto const& orderA = _a.state.contractCreationOrder;
	auto const& orderB = _b.state.contractCreationOrder;
	if (normalizedSubCalls(_a.deploySubCalls, orderA) != normalizedSubCalls(_b.deploySubCalls, orderB))
		out.differences.push_back("deploy outgoing calls differ");
	for (std::size_t i = 0; i < std::min(_a.calls.size(), _b.calls.size()); ++i)
	{
		CallObservation const& a = _a.calls[i];
		CallObservation const& b = _b.calls[i];
		if (a.status == EVMC_OUT_OF_GAS || b.status == EVMC_OUT_OF_GAS || a.subCallOutOfGas || b.subCallOutOfGas)
			return out.skipped = "out of gas in call #" + std::to_string(i), out;
		std::string const call = "call #" + std::to_string(i);
		if (a.status != b.status)
			out.differences.push_back(call + " status differs (" + std::to_string(a.status) + " vs " +
				std::to_string(b.status) + ")");
		else if (!outputEqual(a.output.data(), a.output.size(), orderA, b.output.data(), b.output.size(), orderB))
			out.differences.push_back(call + (a.status == EVMC_SUCCESS ? " output differs" : " revert data differs"));
		if (a.status == b.status && normalizedSubCalls(a.subCalls, orderA) != normalizedSubCalls(b.subCalls, orderB))
			out.differences.push_back(call + " outgoing calls differ");
		if (!transientStorageEqual(a.transientStorage, orderA, b.transientStorage, orderB))
			out.differences.push_back(call + " transient storage differs");
		if (a.storage && b.storage)
		{
			auto storageA = *a.storage;
			auto storageB = *b.storage;
			if (
				maskInternalFunctionPointers(storageA, _a.state.storageLayouts, _a.state.accountCodeHashes) &&
				maskInternalFunctionPointers(storageB, _b.state.storageLayouts, _b.state.accountCodeHashes) &&
				!storageEqual(storageA, orderA, storageB, orderB)
			)
				out.differences.push_back(call + " storage differs");
		}
	}
	if (_a.calls.size() != _b.calls.size())
		out.differences.push_back("number of executed calls differs");
	if (!logsEqual(_a.state.logs, orderA, _b.state.logs, orderB))
		out.differences.push_back("logs differ");
	auto normalizedBalances = [](Execution const& _e) {
		std::map<std::string, std::string> out;
		for (auto const& [address, balance]: _e.balances)
		{
			// An account can exist in one config only because its code path touched it
			if (balance == evmc::bytes32{})
				continue;
			bytes const raw(address.bytes, address.bytes + 20);
			out[util::toHex(normalizeCreatedAddresses(raw.data(), raw.size(), _e.state.contractCreationOrder))] =
				util::toHex(EVMHost::convertFromEVMC(balance).asBytes());
		}
		return out;
	};
	if (normalizedBalances(_a) != normalizedBalances(_b))
		out.differences.push_back("balances differ");

	// Internal function pointers are PCs in legacy and IDs in IR and move with bytecode size
	auto storageA = _a.state.storage;
	auto storageB = _b.state.storage;
	out.storageUnmaskable =
		!maskInternalFunctionPointers(storageA, _a.state.storageLayouts, _a.state.accountCodeHashes) ||
		!maskInternalFunctionPointers(storageB, _b.state.storageLayouts, _b.state.accountCodeHashes);
	if (!out.storageUnmaskable && !storageEqual(storageA, orderA, storageB, orderB))
		out.differences.push_back("storage differs");
	return out;
}

namespace
{

using namespace solidity::frontend;

/// Calls a user-defined function (which may read or write any state) or, unless @a callsOnly, reads a state variable
struct ReadsState: ASTConstVisitor
{
	explicit ReadsState(bool _callsOnly): callsOnly(_callsOnly) {}
	bool callsOnly;
	bool found = false;
	bool visit(FunctionCall const& _call) override
	{
		if (*_call.annotation().kind == FunctionCallKind::FunctionCall)
			if (auto const* type = dynamic_cast<FunctionType const*>(_call.expression().annotation().type))
				if (type->kind() == FunctionType::Kind::Internal || type->kind() == FunctionType::Kind::External ||
					type->kind() == FunctionType::Kind::DelegateCall)
					found = true;
		return !found;
	}
	bool visit(Identifier const& _identifier) override
	{
		auto const* var = dynamic_cast<VariableDeclaration const*>(_identifier.annotation().referencedDeclaration);
		if (!callsOnly && var && var->isStateVariable() && !var->isConstant())
			found = true;
		return false;
	}
};

bool reads(ASTNode const& _node, bool _callsOnly)
{
	ReadsState visitor(_callsOnly);
	_node.accept(visitor);
	return visitor.found;
}

struct PlaceholderRuns: ASTConstVisitor
{
	int runs = 0;
	int loops = 0;
	bool visit(PlaceholderStatement const&) override { runs += loops ? 2 : 1; return false; }
	bool visit(ForStatement const&) override { ++loops; return true; }
	void endVisit(ForStatement const&) override { --loops; }
	bool visit(WhileStatement const&) override { ++loops; return true; }
	void endVisit(WhileStatement const&) override { --loops; }
};

}

namespace
{
struct HasInlineAssembly: ASTConstVisitor
{
	bool found = false;
	bool visit(InlineAssembly const&) override { found = true; return false; }
};

/// Inline assembly can break the invariants solc's codegen and optimizer rely on (memory safety, stack layout), so
/// differences it causes are not compiler bugs. Only code a call graph reaches counts: libraries such as OpenZeppelin's
/// carry assembly in helpers most contracts never call.
bool reachesInlineAssembly(CompilerStack const& _compiler)
{
	for (std::string const& name: _compiler.contractNames())
	{
		auto const& annotation = _compiler.contractDefinition(name).annotation();
		for (auto const* graph: {&annotation.creationCallGraph, &annotation.deployedCallGraph})
		{
			if (!graph->set())
				return true;
			for (auto const& [caller, callees]: (**graph)->edges)
				for (auto const& node: callees)
					if (auto const* const* callable = std::get_if<CallableDeclaration const*>(&node))
					{
						HasInlineAssembly visitor;
						(*callable)->accept(visitor);
						if (visitor.found)
							return true;
					}
		}
	}
	return false;
}
}

std::optional<std::string> afl::configDependentSemantics(
	CompilerStack const& _compiler, bool _legacyVsIR, bool _legacyOptimizer)
{
	if (reachesInlineAssembly(_compiler))
		return "reachable inline assembly";
	if (_legacyOptimizer)
		for (auto const& error: _compiler.errors())
			if (error->errorId() == langutil::ErrorId{3075})
				return "compares internal function pointers";
	if (!_legacyVsIR)
		return std::nullopt;
	for (std::string const& name: _compiler.contractNames())
	{
		// Legacy runs each contract's initializers right before its constructor, base first; IR runs all
		// initializers, then all constructors
		auto const& linearized = _compiler.contractDefinition(name).annotation().linearizedBaseContracts;
		bool baseConstructorRan = false;
		bool baseConstructorCalls = false;
		for (auto it = linearized.rbegin(); it != linearized.rend(); ++it)
		{
			if (baseConstructorRan)
				for (VariableDeclaration const* var: (*it)->stateVariables())
					if (var->value() && (baseConstructorCalls || reads(*var->value(), false)))
						return "state variable initialization order (" + name + ")";
			if (FunctionDefinition const* constructor = (*it)->constructor())
			{
				baseConstructorRan = true;
				baseConstructorCalls = baseConstructorCalls || reads(*constructor, true);
			}
			for (ModifierDefinition const* modifier: (*it)->functionModifiers())
			{
				PlaceholderRuns placeholder;
				modifier->accept(placeholder);
				if (placeholder.runs > 1)
					return "modifier " + modifier->name() + " may run its body more than once (" + name + ")";
			}
		}
	}
	return std::nullopt;
}

namespace
{

struct IdentityWrapper: ASTConstVisitor
{
	IdentityWrapper(util::h256 const& _seed, std::size_t _unit): rng(seedOf(_seed)), unit(_unit) {}

	static uint64_t seedOf(util::h256 const& _seed)
	{
		uint64_t value = 0;
		for (std::size_t i = 0; i < 8; ++i)
			value = (value << 8) | _seed[i];
		return value;
	}

	struct Edit
	{
		std::size_t start;
		std::size_t end;
		std::string helper;
	};
	std::mt19937_64 rng;
	std::size_t unit;
	std::vector<Edit> edits;
	std::map<std::string, std::string> helpers; ///< name -> definition

	/// Pre-order, so an enclosing expression comes before the ones inside it
	std::vector<std::pair<Expression const*, std::string>> candidates;

	bool visitNode(ASTNode const& _node) override
	{
		auto const* expression = dynamic_cast<Expression const*>(&_node);
		if (expression && candidate(*expression))
			candidates.emplace_back(expression, expression->annotation().type->toString(true));
		return true;
	}

	/// About a quarter of the candidates, at least one, none nested in another
	void choose()
	{
		std::vector<bool> chosen(candidates.size());
		for (std::size_t i = 0; i < candidates.size(); ++i)
			chosen[i] = rng() % 4 == 0;
		if (!candidates.empty() && std::find(chosen.begin(), chosen.end(), true) == chosen.end())
			chosen[rng() % candidates.size()] = true;
		for (std::size_t i = 0; i < candidates.size(); ++i)
		{
			auto const& location = candidates[i].first->location();
			auto const start = static_cast<std::size_t>(location.start);
			auto const end = static_cast<std::size_t>(location.end);
			// Pre-order: whatever is nested in a chosen expression directly follows it
			if (!chosen[i] || (!edits.empty() && start >= edits.back().start && end <= edits.back().end))
				continue;
			std::string const& typeName = candidates[i].second;
			// Identities through different code paths: plain, ABI encoder/decoder, memory allocation
			static char const* const kinds[] = {"id", "id", "abi", "mem"};
			std::string const kind = kinds[rng() % 4];
			std::string name = "__" + kind + std::to_string(unit) + "_";
			for (char c: typeName)
				name += std::isalnum(static_cast<unsigned char>(c)) ? c : '_';
			std::string const body =
				kind == "abi" ? "return abi.decode(abi.encode(v), (" + typeName + "));" :
				kind == "mem" ? typeName + "[] memory a = new " + typeName + "[](1); a[0] = v; return a[0];" :
				"return v;";
			helpers[name] = "function " + name + "(" + typeName + " v) pure returns (" + typeName + ") { " + body + " }";
			edits.push_back({start, end, name});
		}
	}

	static bool candidate(Expression const& _expression)
	{
		auto const& annotation = _expression.annotation();
		if (!annotation.type || annotation.willBeWrittenTo || _expression.location().start < 0)
			return false;
		// Literals stay literals: wrapping would change type inference
		switch (annotation.type->category())
		{
		case Type::Category::Integer:
		case Type::Category::Bool:
		case Type::Category::Address:
		case Type::Category::FixedBytes:
			return true;
		default:
			return false;
		}
	}
};

}

std::optional<StringMap> afl::wrapInIdentityCalls(CompilerStack const& _compiler, util::h256 const& _seed)
{
	StringMap out;
	bool changed = false;
	std::size_t unit = 0;
	for (std::string const& name: _compiler.sourceNames())
	{
		std::string source = _compiler.charStream(name).source();
		IdentityWrapper wrapper(util::keccak256(_seed.asBytes() + util::asBytes(name)), unit++);
		for (auto const* function: ASTNode::filteredNodes<FunctionDefinition>(_compiler.ast(name).nodes()))
			if (function->isImplemented())
				function->body().accept(wrapper);
		for (auto const* contract: ASTNode::filteredNodes<ContractDefinition>(_compiler.ast(name).nodes()))
		{
			for (FunctionDefinition const* function: contract->definedFunctions())
				if (function->isImplemented())
					function->body().accept(wrapper);
			for (ModifierDefinition const* modifier: contract->functionModifiers())
				if (modifier->isImplemented())
					modifier->body().accept(wrapper);
		}
		wrapper.choose();
		std::sort(wrapper.edits.begin(), wrapper.edits.end(), [](auto const& _a, auto const& _b) { return _a.start > _b.start; });
		for (auto const& edit: wrapper.edits)
		{
			if (edit.end > source.size() || edit.start >= edit.end)
				return std::nullopt;
			source.insert(edit.end, ")");
			source.insert(edit.start, edit.helper + "(");
		}
		for (auto const& [_, definition]: wrapper.helpers)
			source += "\n" + definition;
		changed = changed || !wrapper.edits.empty();
		out[name] = std::move(source);
	}
	return changed ? std::optional<StringMap>(std::move(out)) : std::nullopt;
}

namespace
{
struct ScopeCollector: ASTConstVisitor
{
	explicit ScopeCollector(langutil::SourceLocation const& _use): use(_use) {}
	langutil::SourceLocation const& use;
	std::vector<std::string> values; ///< variables of elementary, non-array type
	std::vector<std::string> otherValues;
	std::vector<std::string> functions;
	std::vector<std::string> types;

	void addVariable(VariableDeclaration const& _var)
	{
		auto const* typeName = _var.hasTypeName() ? dynamic_cast<ElementaryTypeName const*>(&_var.typeName()) : nullptr;
		bool const elementary = typeName && typeName->typeName().token() != langutil::Token::String &&
			typeName->typeName().token() != langutil::Token::Bytes;
		(elementary ? values : otherValues).push_back(_var.name());
	}

	bool contains(ASTNode const& _node) const
	{
		return _node.location().start <= use.start && use.end <= _node.location().end;
	}
	bool visit(ContractDefinition const& _contract) override
	{
		types.push_back(_contract.name());
		if (contains(_contract))
		{
			for (auto const* var: _contract.stateVariables())
				addVariable(*var);
			for (auto const* function: _contract.definedFunctions())
				if (!function->name().empty())
					functions.push_back(function->name());
		}
		return contains(_contract);
	}
	bool visit(StructDefinition const& _struct) override { types.push_back(_struct.name()); return false; }
	bool visit(EnumDefinition const& _enum) override { types.push_back(_enum.name()); return false; }
	bool visit(UserDefinedValueTypeDefinition const& _type) override { types.push_back(_type.name()); return false; }
	bool visit(SourceUnit const& _unit) override
	{
		// Free functions; their scope annotation may be missing after failed name resolution
		for (auto const* function: ASTNode::filteredNodes<FunctionDefinition>(_unit.nodes()))
			if (!function->name().empty())
				functions.push_back(function->name());
		return true;
	}
	bool visit(FunctionDefinition const& _function) override { return contains(_function); }
	bool visit(ModifierDefinition const& _modifier) override { return contains(_modifier); }
	bool visit(VariableDeclaration const& _var) override
	{
		// Parameters and locals declared before the use; block scoping is approximated by position
		if (!_var.isStateVariable() && !_var.name().empty() && _var.location().end <= use.start)
			addVariable(_var);
		return false;
	}
};
}

std::optional<StringMap> afl::repairUndeclaredIdentifiers(CompilerStack const& _compiler, StringMap const& _sources)
{
	if (_compiler.state() < CompilerStack::Parsed)
		return std::nullopt;
	std::map<std::string, std::vector<std::pair<langutil::SourceLocation, std::string>>> edits;
	for (auto const& error: _compiler.errors())
	{
		if (error->type() != langutil::Error::Type::DeclarationError || !error->comment())
			continue;
		bool const value = error->comment()->starts_with("Undeclared identifier");
		if (!value && !error->comment()->starts_with("Identifier not found or not unique"))
			continue;
		auto const* location = error->sourceLocation();
		if (!location || !location->sourceName || location->start < 0 || location->end <= location->start ||
			!_sources.contains(*location->sourceName))
			continue;
		ScopeCollector scope(*location);
		_compiler.ast(*location->sourceName).accept(scope);
		std::string const& source = _sources.at(*location->sourceName);
		std::string const used = source.substr(static_cast<std::size_t>(location->start),
			static_cast<std::size_t>(location->end - location->start));
		std::size_t next = static_cast<std::size_t>(location->end);
		while (next < source.size() && std::isspace(static_cast<unsigned char>(source[next])))
			++next;
		bool const called = next < source.size() && source[next] == '(';
		// solc's own suggestions (`Did you mean "a" or "b"?`) are names close to the one used
		std::vector<std::string> candidates;
		for (std::size_t q = error->comment()->find('"'); q != std::string::npos; q = error->comment()->find('"', q))
		{
			std::size_t const end = error->comment()->find('"', q + 1);
			if (end == std::string::npos)
				break;
			candidates.push_back(error->comment()->substr(q + 1, end - q - 1));
			q = end + 1;
		}
		if (candidates.empty())
			candidates = !value ? scope.types : called ? scope.functions : !scope.values.empty() ? scope.values : scope.otherValues;
		if (candidates.empty())
			continue;
		h256 const pick = keccak256(used + std::to_string(location->start));
		edits[*location->sourceName].emplace_back(*location, candidates[pick[0] % candidates.size()]);
	}
	if (edits.empty())
		return std::nullopt;
	StringMap out = _sources;
	for (auto& [unit, unitEdits]: edits)
	{
		std::sort(unitEdits.begin(), unitEdits.end(), [](auto const& _a, auto const& _b) { return _a.first.start > _b.first.start; });
		std::string& source = out[unit];
		int previousStart = std::numeric_limits<int>::max();
		for (auto const& [location, name]: unitEdits)
			if (location.end <= previousStart && static_cast<std::size_t>(location.end) <= source.size())
			{
				source.replace(static_cast<std::size_t>(location.start), static_cast<std::size_t>(location.end - location.start), name);
				previousStart = location.start;
			}
	}
	return out == _sources ? std::nullopt : std::optional<StringMap>(std::move(out));
}
