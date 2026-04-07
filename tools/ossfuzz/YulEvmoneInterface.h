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

#pragma once

#include <tools/common/EVMHost.h>

#include <libyul/YulStack.h>

#include <libsolidity/interface/OptimiserSettings.h>

#include <liblangutil/DebugInfoSelection.h>

namespace solidity::test::fuzzer
{
class YulAssembler
{
public:
	YulAssembler(
		langutil::EVMVersion _evmVersion,
		std::optional<uint8_t> _eofVersion,
		solidity::frontend::OptimiserSettings _optSettings,
		std::string const& _yulSource,
		bool _viaSSACFG = false
	):
		m_stack(
			_evmVersion,
			_eofVersion,
			_optSettings,
			langutil::DebugInfoSelection::All()
		),
		m_yulProgram(_yulSource),
		m_optimiseYul(_optSettings.runYulOptimiser),
		m_viaSSACFG(_viaSSACFG)
	{}
	solidity::bytes assemble();
	/// Parses, analyzes, and optionally optimizes the Yul source.
	/// Must be called before assembleOnly() or printIR().
	void parseAndOptimize();
	/// Assembles to bytecode. Must be called after parseAndOptimize().
	solidity::bytes assembleOnly();
	/// @returns the Yul IR as a string (optimized if optimization was enabled).
	/// Must be called after parseAndOptimize().
	std::string printIR() const;
	std::shared_ptr<yul::Object> object();
private:
	solidity::yul::YulStack m_stack;
	std::string m_yulProgram;
	bool m_optimiseYul;
	bool m_viaSSACFG;
};

struct YulEvmoneUtility
{
	/// @returns the result of deploying bytecode @param _input on @param _host.
	static evmc::Result deployCode(solidity::bytes const& _input, EVMHost& _host, int64_t _gas = std::numeric_limits<int64_t>::max());
	/// @returns call message to be sent to @param _address.
	static evmc_message callMessage(evmc_address _address);
	/// @returns call message to be sent to @param _address with @param _calldata.
	static evmc_message callMessage(evmc_address _address, solidity::bytes const& _calldata);
	/// @returns true if call result indicates a serious error, false otherwise.
	static bool seriousCallError(evmc_status_code _code);
};
}
