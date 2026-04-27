#pragma once
//
// Minimal facade to register a custom evmone::Tracer on a dlopen'd libevmone.so
// without including evmone's private lib/* headers (which transitively pull in
// the full intx::uint256 definition via execution_state.hpp).
//
// Layout MUST match evmone/lib/evmone/{tracing,vm}.hpp:
//   class Tracer { vtable*, unique_ptr<Tracer> m_next_tracer; ... };
//   class VM : evmc_vm { bool cgoto; vector<ExecutionState> m_execution_states;
//                        unique_ptr<Tracer> m_first_tracer; };
//
// We only access m_first_tracer (an offset away from the evmc_vm base) and we
// never construct or destroy a VM ourselves — libevmone.so does both. Vector
// of forward-declared T is fine in libstdc++ as long as no member of vector is
// instantiated.
//
// The Tracer class declared here is the SAME C++ type as evmone::Tracer
// (identical declaration in the same namespace), per the One Definition Rule.

#include <test/evmc/bytes.hpp>
#include <test/evmc/evmc.h>
#include <test/evmc/evmc.hpp>

#include <cstdint>
#include <memory>
#include <vector>

namespace intx
{
template <unsigned N> struct uint;
}

namespace evmone
{

class VMLayout;
class ExecutionState;

class Tracer
{
	friend class VMLayout;
	std::unique_ptr<Tracer> m_next_tracer;

public:
	virtual ~Tracer() = default;

	void notify_execution_start(
		evmc_revision _rev, evmc_message const& _msg, evmc::bytes_view _code) noexcept
	{
		on_execution_start(_rev, _msg, _code);
		if (m_next_tracer)
			m_next_tracer->notify_execution_start(_rev, _msg, _code);
	}
	void notify_execution_end(evmc_result const& _result) noexcept
	{
		on_execution_end(_result);
		if (m_next_tracer)
			m_next_tracer->notify_execution_end(_result);
	}
	void notify_instruction_start(
		uint32_t _pc,
		intx::uint<256>* _stack_top,
		int _stack_height,
		int64_t _gas,
		ExecutionState const& _state) noexcept
	{
		on_instruction_start(_pc, _stack_top, _stack_height, _gas, _state);
		if (m_next_tracer)
			m_next_tracer->notify_instruction_start(_pc, _stack_top, _stack_height, _gas, _state);
	}

private:
	virtual void on_execution_start(
		evmc_revision _rev, evmc_message const& _msg, evmc::bytes_view _code) noexcept = 0;
	virtual void on_instruction_start(
		uint32_t _pc,
		intx::uint<256> const* _stack_top,
		int _stack_height,
		int64_t _gas,
		ExecutionState const& _state) noexcept = 0;
	virtual void on_execution_end(evmc_result const& _result) noexcept = 0;
};

/// Layout-compatible mirror of evmone::VM. We use this only to compute the
/// offset of m_first_tracer; we never construct an instance.
class VMLayout : public evmc_vm
{
public:
	bool cgoto;

private:
	std::vector<ExecutionState> m_execution_states;

public:
	std::unique_ptr<Tracer> m_first_tracer;

	void addTracer(std::unique_ptr<Tracer> _tracer) noexcept
	{
		auto* end = &m_first_tracer;
		while (*end)
			end = &(*end)->m_next_tracer;
		*end = std::move(_tracer);
	}

	void removeAllTracers() noexcept { m_first_tracer.reset(); }
};

inline void addTracer(evmc::VM& _vm, std::unique_ptr<Tracer> _tracer) noexcept
{
	static_cast<VMLayout*>(_vm.get_raw_pointer())->addTracer(std::move(_tracer));
}

inline void removeAllTracers(evmc::VM& _vm) noexcept
{
	static_cast<VMLayout*>(_vm.get_raw_pointer())->removeAllTracers();
}

}  // namespace evmone
