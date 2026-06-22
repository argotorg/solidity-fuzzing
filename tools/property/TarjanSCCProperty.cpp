/*
 * Property test for TarjanSCC.
 *
 *   1. Partition: the SCCs partition the node set [0, N), i.e., every node appears in exactly one SCC.
 *   2. Correctness: two nodes share an SCC iff they are mutually reachable.
 *   3. Reverse-topological order: for every edge u -> v that crosses SCC boundaries, u's SCC is emitted after v's.
 */

#include <libyul/backends/evm/ssa/util/TarjanSCC.h>

#include <fuzztest/fuzztest.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace
{

using NodeID = std::uint32_t;

struct Edge
{
	std::uint32_t from;
	std::uint32_t to;
};

constexpr std::uint32_t kMaxNodes = 128;
constexpr std::uint32_t kMaxEdges = 256;

using solidity::yul::ssa::util::computeStronglyConnectedComponents;

}

void SCCMatchesReachability(std::uint32_t _numNodes, std::vector<Edge> const& _edges)
{
	NodeID const n = std::clamp<std::uint32_t>(_numNodes, 1, kMaxNodes);

	std::vector<std::vector<NodeID>> adjacency(n);
	for (const auto& [from, to]: _edges)
		adjacency[from % n].push_back(to % n);

	std::vector<std::vector<NodeID>> const sccs = computeStronglyConnectedComponents<NodeID>(adjacency);

	// SCCs partition [0, n): assign each node n it's corresponding SCC
	std::vector<std::int64_t> sccOfNode(n, -1);
	for (std::size_t sccIndex = 0; sccIndex < sccs.size(); ++sccIndex)
		for (NodeID const node: sccs[sccIndex])
		{
			ASSERT_LT(node, n) << "SCC contains out-of-range node " << node;
			ASSERT_EQ(sccOfNode[node], -1) << "node " << node << " appears in multiple SCCs";
			ASSERT_LT(sccIndex, std::numeric_limits<std::int64_t>::max());
			sccOfNode[node] = static_cast<std::int64_t>(sccIndex);
		}
	for (NodeID i = 0; i < n; ++i)
		ASSERT_NE(sccOfNode[i], -1) << "node " << i << " missing from SCC partition";

	// reach[s] = the set of nodes reachable from s, computed by one independent DFS per source
	std::vector reach(n, std::vector<std::uint8_t>(n, false));
	for (NodeID source = 0; source < n; ++source)
	{
		std::vector<NodeID> stack{source};
		reach[source][source] = true;
		while (!stack.empty())
		{
			NodeID const u = stack.back();
			stack.pop_back();
			for (NodeID const v: adjacency[u])
				if (!reach[source][v])
				{
					reach[source][v] = true;
					stack.push_back(v);
				}
		}
	}

	// same SCC iff mutually reachable
	for (NodeID i = 0; i < n; ++i)
		for (NodeID j = 0; j < n; ++j)
		{
			bool const sameSCC = sccOfNode[i] == sccOfNode[j];
			bool const mutuallyReachable = reach[i][j] && reach[j][i];
			ASSERT_EQ(sameSCC, mutuallyReachable)
				<< "nodes " << i << " and " << j << ": sameSCC=" << sameSCC
				<< " mutuallyReachable=" << mutuallyReachable;
		}

	// reverse-topological emission order
	for (NodeID u = 0; u < n; ++u)
		for (NodeID const v: adjacency[u])
			if (sccOfNode[u] != sccOfNode[v])
				ASSERT_GT(sccOfNode[u], sccOfNode[v])
					<< "edge " << u << "->" << v << " crosses SCCs but source SCC "
					<< sccOfNode[u] << " is not emitted after target SCC " << sccOfNode[v];
}

FUZZ_TEST(TarjanSCCProperty, SCCMatchesReachability)
	.WithDomains(
		fuzztest::InRange<std::uint32_t>(1, kMaxNodes),
		fuzztest::VectorOf(
			fuzztest::StructOf<Edge>(
				fuzztest::Arbitrary<std::uint32_t>(),
				fuzztest::Arbitrary<std::uint32_t>()
			)
		).WithMaxSize(kMaxEdges)
	);
