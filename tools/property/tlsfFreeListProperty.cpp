/*
 * Property test for solidity::yul::ssa::util::TLSFFreeList.
 *
 * Drives a fuzz-generated sequence of allocate/deallocate operations against a
 * fresh TLSFFreeList<TestItem, TestItemTombstone> while keeping an oracle map
 * (creation-time -> live item) in lockstep. After every step we assert two
 * invariants:
 *
 *   1. Set equality: the set of non-tombstone slots in the allocator equals the
 *      union of [start, start+length) over every live oracle entry.
 *   2. No pollution: each live item's slot range is exclusively filled with
 *      that item's payload (no tombstones, no foreign payloads).
 *
 * Catches coalescing/split mistakes that would corrupt InstructionStore
 * downstream in the Yul SSA backend.
 */

#include <libyul/backends/evm/ssa/util/TLSFFreeList.h>

#include <fuzztest/fuzztest.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <iterator>
#include <map>
#include <vector>

namespace
{

struct TestItem
{
	std::uint64_t payload = 0;
	bool isTombstone = true;
};

struct TestItemTombstone
{
	static TestItem make() noexcept { return TestItem{0, true}; }
	static bool isTombstone(TestItem const& _i) noexcept { return _i.isTombstone; }
};

struct Op
{
	bool isAlloc;
	std::uint32_t length;
	std::uint32_t pickIndex;
};

struct LiveItem
{
	std::uint32_t start;
	std::uint32_t length;
	std::uint64_t payload;
};

constexpr std::uint32_t kMaxAllocLength = 256;
constexpr std::uint32_t kMinOps = 1;
constexpr std::uint32_t kMaxOps = 512;
constexpr std::uint32_t kMaxTotalSlots = 64u * 1024u;

using solidity::yul::ssa::util::TLSFFreeList;

} // anonymous namespace

void SetAndPollutionInvariance(std::vector<Op> const& ops)
{
	TLSFFreeList<TestItem, TestItemTombstone> freeList;

	std::map<std::uint64_t, LiveItem> oracle;
	std::uint64_t nextCreationTime = 1;
	std::uint64_t nextPayload = 1;

	auto doDealloc = [&](std::uint32_t _pickIndex)
	{
		auto it = std::next(oracle.begin(), _pickIndex % oracle.size());
		freeList.deallocate(it->second.start, it->second.length);
		oracle.erase(it);
	};

	auto doAlloc = [&](std::uint32_t _length)
	{
		std::uint64_t const payload = nextPayload++;
		std::uint32_t const start = freeList.allocate(_length);
		for (std::uint32_t i = 0; i < _length; ++i)
			freeList[start + i] = TestItem{payload, false};
		oracle.emplace(nextCreationTime++, LiveItem{start, _length, payload});
	};

	for (Op const& op : ops)
	{
		std::uint32_t const length = std::clamp<std::uint32_t>(op.length, 1, kMaxAllocLength);

		if (op.isAlloc)
		{
			bool const wouldOverflow = freeList.size() + length > kMaxTotalSlots;
			if (wouldOverflow && oracle.empty())
				continue;
			if (wouldOverflow)
				doDealloc(op.pickIndex);
			else
				doAlloc(length);
		}
		else
		{
			if (oracle.empty())
				continue;
			doDealloc(op.pickIndex);
		}

		// ---- Invariant 1: set equality of occupied slots ----
		std::vector oracleOccupied(freeList.size(), false);
		for (const auto& item: oracle | std::views::values)
		{
			for (std::uint32_t i = 0; i < item.length; ++i)
			{
				std::uint32_t const slotIdx = item.start + i;
				ASSERT_LT(slotIdx, freeList.size())
					<< "oracle item extends past freeList end (start=" << item.start
					<< ", length=" << item.length << ", size=" << freeList.size() << ")";
				ASSERT_FALSE(oracleOccupied[slotIdx])
					<< "oracle bookkeeping bug: double-claimed slot " << slotIdx;
				oracleOccupied[slotIdx] = true;
			}
		}

		for (std::uint32_t i = 0; i < freeList.size(); ++i)
		{
			bool const isTomb = TestItemTombstone::isTombstone(freeList[i]);
			ASSERT_EQ(!isTomb, oracleOccupied[i])
				<< "slot " << i << ": freeList tombstone-bit disagrees with oracle (isTomb="
				<< isTomb << ", oracleOccupied=" << oracleOccupied[i] << ")";
		}

		// ---- Invariant 2: per-item, no pollution ----
		for (const auto& item: oracle | std::views::values)
		{
			for (std::uint32_t i = 0; i < item.length; ++i)
			{
				TestItem const& slot = freeList[item.start + i];
				ASSERT_FALSE(slot.isTombstone)
					<< "live item at " << item.start << " polluted by tombstone at "
					<< (item.start + i);
				ASSERT_EQ(slot.payload, item.payload)
					<< "live item at " << item.start << " polluted by foreign payload at "
					<< (item.start + i) << " (expected " << item.payload
					<< ", got " << slot.payload << ")";
			}
		}
	}
}

FUZZ_TEST(TLSFFreeListProperty, SetAndPollutionInvariance)
	.WithDomains(
		fuzztest::VectorOf(
			fuzztest::StructOf<Op>(
				fuzztest::Arbitrary<bool>(),
				fuzztest::InRange<std::uint32_t>(1, kMaxAllocLength),
				fuzztest::Arbitrary<std::uint32_t>()
			)
		).WithMinSize(kMinOps).WithMaxSize(kMaxOps)
	);
