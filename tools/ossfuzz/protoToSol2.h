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

#include <tools/ossfuzz/sol2Proto.pb.h>

#include <random>
#include <string>
#include <vector>
#include <map>
#include <memory>
#include <sstream>

namespace solidity::test::sol2protofuzzer
{

/// Random number generator seeded by fuzzer-supplied seed.
struct SolRandomNumGenerator
{
	using RandomEngine = std::minstd_rand;

	explicit SolRandomNumGenerator(unsigned _seed): m_random(RandomEngine(_seed)) {}

	unsigned operator()()
	{
		return static_cast<unsigned>(m_random());
	}

	RandomEngine m_random;
};

class ProtoConverter
{
public:
	ProtoConverter() = default;
	ProtoConverter(ProtoConverter const&) = delete;
	ProtoConverter(ProtoConverter&&) = delete;

	/// Convert a protobuf Program to Solidity source code.
	std::string protoToSolidity(Program const& _p);

private:
	// ===== Internal info types =====

	struct FuncInfo
	{
		std::string name;
		unsigned numParams;
		Visibility vis;
		StateMutability mut;
		/// Per-parameter types (size == numParams).
		std::vector<ParamType> paramTypes;
		/// When true, function returns (uint256, uint256) instead of uint256.
		bool returnTwo = false;
	};

	struct FreeFuncInfo
	{
		std::string name;
		unsigned numParams;
	};

	struct EventInfo
	{
		std::string name;
		unsigned numParams;
		/// Per-parameter indexed flags (size == numParams, max 3 true)
		std::vector<bool> indexedParams;
	};

	struct ErrorInfo
	{
		std::string name;
		unsigned numParams;
		std::vector<std::string> paramNames;
	};

	struct ModifierInfo
	{
		std::string name;
	};

	struct StructFieldInfo
	{
		std::string name;
		std::string typeStr;
		bool isUintCompatible;
	};

	struct StructDefInfo
	{
		std::string name;
		std::vector<StructFieldInfo> fields;
	};

	struct EnumDefInfo
	{
		std::string name;
		unsigned numMembers;
		std::vector<std::string> memberNames;
	};

	struct StateVarInfo
	{
		std::string name;
		std::string typeStr;
		bool isUint = false;
		bool isStruct = false;
		unsigned structDefIdx = 0;
		// Array tracking
		bool isArray = false;
		bool isFixedArray = false;
		unsigned arrayLength = 0;
		// Mapping tracking
		bool isMapping = false;
		std::string mappingKeyTypeStr;
		// For arrays/mappings: whether the element/value type is uint-compatible
		bool elementIsUint = false;
		// Transient storage (tstore/tload)
		bool isTransient = false;
		// Compile-time constant
		bool isConstant = false;
		// Set once in constructor
		bool isImmutable = false;
	};

	struct ContractInfo
	{
		std::string name;
		ContractDef::Kind kind;
		std::vector<FuncInfo> functions;
		std::vector<StateVarInfo> stateVars;
		std::vector<EventInfo> events;
		std::vector<ErrorInfo> errors;
		std::vector<ModifierInfo> modifiers;
		std::vector<StructDefInfo> structDefs;
		std::vector<EnumDefInfo> enumDefs;
		/// Indices of base contracts in m_contracts (empty if no bases).
		/// Ordered from most base-like to most derived-like for C3 linearization.
		std::vector<unsigned> baseIndices;
		bool hasReceive = false;
		bool hasFallback = false;
		bool hasCtorParam = false;
	};

	// ===== Visitor methods =====

	std::string visit(Program const& _p);
	std::string visitContract(ContractDef const& _c, unsigned _idx);
	std::string visitFunction(FunctionDef const& _f, ContractInfo const& _cinfo, unsigned _funcIdx);
	std::string visitBlock(Block const& _b);
	std::string visitStatement(Statement const& _s);

	// Statement visitors
	std::string visitVarDecl(VarDeclStmt const& _s);
	std::string visitExprStmt(ExprStmt const& _s);
	std::string visitIf(IfStmt const& _s);
	std::string visitFor(ForStmt const& _s);
	std::string visitWhile(WhileStmt const& _s);
	std::string visitDoWhile(DoWhileStmt const& _s);
	std::string visitReturn(ReturnStmt const& _s);
	std::string visitEmit(EmitStmt const& _s);
	std::string visitRevert(RevertStmt const& _s);
	std::string visitRequire(RequireStmt const& _s);
	std::string visitUnchecked(UncheckedBlock const& _s);
	std::string visitDelete(DeleteStmt const& _s);
	std::string visitTryCatch(TryCatchStmt const& _s);
	std::string visitIndexAssign(IndexAssignStmt const& _s);
	std::string visitTupleAssign(TupleAssignStmt const& _s);
	std::string visitArrayPush(ArrayPushStmt const& _s);
	std::string visitArrayPop(ArrayPopStmt const& _s);
	std::string visitTupleDestruct(TupleDestructStmt const& _s);

	// Expression visitors — generate uint256-typed or bool-typed expressions
	std::string visitUintExpr(Expression const& _e);
	std::string visitBoolExpr(Expression const& _e);

	// ===== Test contract =====
	std::string generateTestContract();

	// ===== Type helpers =====
	std::string elementaryTypeStr(ElementaryType const& _t);
	std::string elementaryTypeStr(TypeName const& _t);
	bool isUintType(TypeName const& _t);
	bool isUintType(ElementaryType const& _t);

	// ===== Scope management =====
	void pushScope();
	void popScope();
	/// Add a uint256 variable to the current scope.
	void addVar(std::string const& _name);
	/// Find a uint256 variable in scope, using _hint to pick one.
	/// Falls back to literal "0" if no variables are in scope.
	std::string findVar(uint32_t _hint);
	/// Find a uint256 variable that is an lvalue (locals + params, not state vars).
	/// Returns empty string if no lvalue variables exist.
	std::string findLVar(uint32_t _hint);
	/// Get all uint256 variables in scope (locals + params + state vars if view/nonpayable).
	std::vector<std::string> allUintVars();
	/// Get all struct state variables accessible in current context.
	std::vector<std::pair<std::string, unsigned>> allStructVars();

	// ===== Helpers =====
	std::string indent();
	unsigned randomNumber();
	std::string defaultUintLiteral();
	std::string defaultBoolLiteral();
	/// Collect inherited state vars, events, errors, structs from base
	void collectInheritedInfo(ContractInfo const& _cinfo);
	/// Set up state for a body block (modifier, receive, fallback, etc.)
	/// and visit the block. Resets scope, var counters, indent, and stmt depth.
	std::string setupAndVisitBlock(
		Block const& _body,
		ContractInfo const& _cinfo,
		StateMutability _mut,
		unsigned _indentLevel
	);

	// Parameter type helpers
	static std::string paramTypeSolStr(ParamType _t);
	static std::string paramTypeAbiStr(ParamType _t);

	// Binary/unary op classification
	static bool isArithmeticOp(BinaryOp::Op _op);
	static bool isBitwiseOp(BinaryOp::Op _op);
	static bool isComparisonOp(BinaryOp::Op _op);
	static bool isLogicalOp(BinaryOp::Op _op);
	static std::string arithmeticOpStr(BinaryOp::Op _op);
	static std::string bitwiseOpStr(BinaryOp::Op _op);
	static std::string comparisonOpStr(BinaryOp::Op _op);
	static std::string logicalOpStr(BinaryOp::Op _op);
	static std::string assignOpStr(AssignExpr::Op _op);

	// ===== Limits =====
	static constexpr unsigned s_maxExprDepth = 2;
	static constexpr unsigned s_maxStmtDepth = 2;
	static constexpr unsigned s_maxLocalVars = 4;
	static constexpr unsigned s_maxContracts = 2;
	static constexpr unsigned s_maxFunctions = 3;
	static constexpr unsigned s_maxStmtsPerBlock = 3;
	static constexpr unsigned s_maxParams = 2;
	static constexpr unsigned s_maxStateVars = 3;
	static constexpr unsigned s_maxEvents = 2;
	static constexpr unsigned s_maxErrors = 2;
	static constexpr unsigned s_maxEventParams = 2;
	static constexpr unsigned s_maxErrorParams = 2;
	static constexpr unsigned s_maxForIter = 3;
	static constexpr unsigned s_maxFreeFunctions = 2;
	static constexpr unsigned s_maxModifiers = 2;
	static constexpr unsigned s_maxStructFields = 3;
	static constexpr unsigned s_maxEnumMembers = 5;
	static constexpr unsigned s_maxStructs = 2;
	static constexpr unsigned s_maxEnums = 2;

	// ===== State =====
	unsigned m_exprDepth = 0;
	unsigned m_stmtDepth = 0;
	unsigned m_indentLevel = 0;
	unsigned m_varCounter = 0;
	unsigned m_localVarCount = 0;
	bool m_inLoop = false;
	bool m_inConstructor = false;
	bool m_inModifier = false;
	bool m_inReceive = false;
	bool m_inFreeFunction = false;
	bool m_inUnchecked = false;
	/// True only inside regular functions (which return uint256).
	/// False in constructors, modifiers, receive, and fallback.
	bool m_canReturn = false;
	/// True when current function returns (uint256, uint256)
	bool m_currentReturnsTwo = false;
	unsigned m_currentFuncIdx = 0;

	/// Info about all generated contracts
	std::vector<ContractInfo> m_contracts;
	/// Current contract index
	unsigned m_currentContract = 0;
	/// Current contract's uint256 state var names (available in view/nonpayable functions)
	std::vector<std::string> m_currentUintStateVars;
	/// Current contract's struct state vars: (name, structDefIdx) pairs
	std::vector<std::pair<std::string, unsigned>> m_currentStructStateVars;
	/// Current contract's indexable state vars (fixed arrays + mappings with uint elements)
	std::vector<StateVarInfo> m_currentIndexableVars;
	/// Current contract's dynamic (non-fixed) array state vars (for push/pop/length)
	std::vector<StateVarInfo> m_currentDynArrayVars;
	/// Whether current function can read state
	bool m_canReadState = false;
	/// Current function's state mutability
	StateMutability m_currentMutability = NONPAYABLE;
	/// Current contract's events
	std::vector<EventInfo> m_currentEvents;
	/// Current contract's errors
	std::vector<ErrorInfo> m_currentErrors;
	/// Current contract's struct definitions (for member access)
	std::vector<StructDefInfo> m_currentStructDefs;
	/// Current contract's enum definitions (for enum literals)
	std::vector<EnumDefInfo> m_currentEnumDefs;
	/// Scope stack: each scope is a list of uint256 variable names
	std::vector<std::vector<std::string>> m_scopeStack;
	/// Whether current contract used _cdl/_cds helpers (emit only if needed)
	bool m_usedCdl = false;
	bool m_usedCds = false;
	/// Whether to use CREATE2 (new C{salt: ...}()) in test contract
	bool m_useCreate2 = false;
	/// Hex-encoded 32-byte salt for CREATE2 (padded/truncated to 32 bytes)
	std::string m_create2SaltHex;
	/// Free functions info
	std::vector<FreeFuncInfo> m_freeFunctions;
	/// Whether we generated a UDVT (type MyUint is uint256)
	bool m_hasUdvt = false;
	/// RNG
	std::shared_ptr<SolRandomNumGenerator> m_randomGen;
};

} // namespace solidity::test::sol2protofuzzer
