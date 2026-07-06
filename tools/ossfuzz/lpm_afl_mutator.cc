// libprotobuf-mutator -> AFL++ custom-mutator bridge.
//
// AFL++'s own engine mutates raw bytes; applied to serialized protobuf that
// destroys the grammar. This custom mutator instead deserializes the
// (text-format) protobuf that DEFINE_PROTO_FUZZER expects, runs
// libprotobuf-mutator's structure-aware Mutator over the message tree, and
// re-serializes — so every generated input stays a valid, grammar-conformant
// program. Run AFL with AFL_CUSTOM_MUTATOR_ONLY=1 so byte-level havoc never
// touches the serialized form.
//
// One .so is built per grammar; LPM_PROTO_HEADER / LPM_PROTO_TYPE select the
// message type at compile time (mirroring how the harnesses bake in their
// FUZZER_MODE_* defines).
//
// It uses the base protobuf_mutator::Mutator (not the libfuzzer-layer
// CustomProtoMutator), so the .so carries no dependency on the fuzzing engine's
// LLVMFuzzerMutate symbol. Text serialization matches DEFINE_PROTO_FUZZER's
// default (use_binary=false), so the harness's LoadProtoInput parses our output
// and the existing libFuzzer corpus is reused unchanged.

#include <cstdint>
#include <string>

#include "src/mutator.h"
#include "src/text_format.h"
#include LPM_PROTO_HEADER

#ifndef LPM_PROTO_TYPE
#error "define LPM_PROTO_TYPE to the fully-qualified protobuf message type"
#endif

namespace {

struct State
{
	protobuf_mutator::Mutator mutator;
	std::string out;  // owns the buffer handed back to AFL until the next call
};

}  // namespace

extern "C" void* afl_custom_init(void* /*afl*/, unsigned int seed)
{
	State* st = new State();
	st->mutator.Seed(seed);
	return st;
}

extern "C" size_t afl_custom_fuzz(
	void* data,
	uint8_t* buf, size_t buf_size,
	uint8_t** out_buf,
	uint8_t* /*add_buf*/, size_t /*add_buf_size*/,
	size_t max_size)
{
	State* st = static_cast<State*>(data);

	LPM_PROTO_TYPE msg;
	// Tolerant parse: on failure msg stays default-constructed and we mutate
	// up from empty, which still yields a valid program.
	protobuf_mutator::ParseTextMessage(buf, buf_size, &msg);
	st->mutator.Mutate(&msg, max_size);
	st->out = protobuf_mutator::SaveMessageAsText(msg);

	// Never hand back a truncated (unparseable) text proto: if the mutation
	// overshot max_size, leave the input unchanged for this exec.
	if (st->out.size() > max_size)
	{
		*out_buf = buf;
		return buf_size;
	}

	*out_buf = reinterpret_cast<uint8_t*>(st->out.data());
	return st->out.size();
}

extern "C" void afl_custom_deinit(void* data)
{
	delete static_cast<State*>(data);
}
