/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * E2E tests for the getRejectedNetworks route walk.
 *
 * These exercise the real path: a real ingress policy denies a route, the
 * route really flows through AdjRibIn, and the walk reports it. Nothing about
 * the rejection is simulated, so these tests would catch a change in how
 * AdjRibEntry represents "policy denied this".
 *
 * Mocked: FIB (TestFib), SessionManager (MockSessionManager)
 * Real: RIB, PeerManagerBase, AdjRib, PolicyManager
 */

#include <gtest/gtest.h>

#include <re2/re2.h>

#include <folly/IPAddress.h>

#include "neteng/fboss/bgp/cpp/tests/Utils.h"
#include "neteng/fboss/bgp/cpp/tests/e2e/E2ETestFixture.h"

using namespace facebook::bgp;
using facebook::neteng::fboss::bgp::thrift::TDirectionFilter;
using facebook::neteng::fboss::bgp_attr::TBgpAfi;
using facebook::neteng::fboss::bgp_attr::TIpPrefix;

namespace facebook::bgp {

namespace {
constexpr auto kDeniedPrefix = "10.0.0.0/8";
constexpr auto kAcceptedPrefix = "20.0.0.0/8";
} // namespace

class E2ERejectedNetworksTest : public E2ETestFixture {
 protected:
  /*
   * Stands up three peers behind an ingress policy that denies `denied`, then
   * brings them all up with EoR. Peer 3 is the only one with a description
   * (kDescription1), which the neighbor-name filter test relies on.
   */
  void setUpWithPrefixDenyPolicy(const std::vector<std::string>& denied) {
    addPrefixDenyPolicy(denied);

    addPeer(kDefaultPeerSpec3);
    addPeer(kDefaultPeerSpec4);
    addPeer(kDefaultPeerSpec5);
    createRib();
    createPeerManager(/*enableUpdateGroup=*/false);

    for (const auto& peerAddr : {kPeerAddr3, kPeerAddr4, kPeerAddr5}) {
      bringUpPeer(peerAddr);
      const BgpPeerId peerId{peerAddr, peerAddr.asV4().toLongHBO()};
      sendEoRToPeer(peerId);
      ASSERT_TRUE(waitForEoR(peerId));
    }
  }

  /*
   * Runs the received-direction walk over every peer the filters select,
   * exactly as the thrift handler does: resolve peers first, then walk each.
   */
  std::vector<RejectedNetwork> walkRejected(
      const re2::RE2* nameFilter = nullptr,
      const re2::RE2* policyFilter = nullptr,
      std::set<TIpPrefix> prefixFilter = {},
      std::optional<TBgpAfi> afi = std::nullopt,
      TDirectionFilter direction = TDirectionFilter::INGRESS) {
    const RejectedNetworksQuery query{
        .direction = direction,
        .policyNameFilter = policyFilter,
        .prefixFilter = std::move(prefixFilter),
        .afi = afi};

    std::vector<RejectedNetwork> all;
    for (const auto& peerId :
         peerManager_->resolveRejectedNetworkPeers(nameFilter, {})) {
      auto perPeer =
          peerManager_->getRejectedNetworksForPeer(peerId, query).entries;
      all.insert(all.end(), perPeer.begin(), perPeer.end());
    }
    return all;
  }

  static TIpPrefix toTIpPrefix(const std::string& cidr) {
    const auto network = folly::IPAddress::createNetwork(cidr);
    TIpPrefix prefix;
    prefix.afi() = network.first.isV4() ? TBgpAfi::AFI_IPV4 : TBgpAfi::AFI_IPV6;
    prefix.num_bits() = network.second;
    prefix.prefix_bin() =
        facebook::network::toBinaryAddress(network.first).addr()->toStdString();
    return prefix;
  }
};

/*
 * A route the ingress policy denied is reported, carrying the name of the
 * policy that denied it.
 */
TEST_F(E2ERejectedNetworksTest, DeniedRouteIsReportedWithPolicyName) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));

  const auto rejected = walkRejected();

  ASSERT_EQ(1, rejected.size());
  EXPECT_EQ(toTIpPrefix(kDeniedPrefix), rejected[0].prefix);
  /*
   * The exact string is produced by the policy engine, so assert the contract
   * the API promises rather than a copy of the engine's output: a rejection by
   * a named policy term always carries that term, never the empty
   * no-term-recorded string.
   */
  EXPECT_FALSE(rejected[0].policyName.empty());
}

/*
 * A route the policy accepted must not be reported. This is the check that
 * fails if the walk ever confuses "no post-policy attributes yet" with
 * "denied".
 */
TEST_F(E2ERejectedNetworksTest, AcceptedRouteIsNotReported) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  addRoute("v4", "20.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  ASSERT_TRUE(waitForRouteInShadowRib(
      folly::IPAddress::createNetwork(kAcceptedPrefix)));

  EXPECT_TRUE(walkRejected().empty());
}

/*
 * A device with nothing denied returns an empty result, not an error.
 */
TEST_F(E2ERejectedNetworksTest, NoRejectionsReturnsEmpty) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  EXPECT_TRUE(walkRejected().empty());
}

/*
 * The same prefix denied on several peers is reported once per peer, so the
 * handler can group it into one entry listing all three neighbors.
 */
TEST_F(E2ERejectedNetworksTest, RejectionReportedForEveryDenyingPeer) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  addRoute("v4", "10.0.0.0", 8, kPeerAddr4, "11.0.0.2", "65001");
  addRoute("v4", "10.0.0.0", 8, kPeerAddr5, "11.0.0.3", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));

  const auto rejected = walkRejected();

  EXPECT_EQ(3, rejected.size());
  for (const auto& entry : rejected) {
    EXPECT_EQ(toTIpPrefix(kDeniedPrefix), entry.prefix);
  }
}

/*
 * neighbor_name_regex narrows the walk to matching peers. Only peer 3 carries
 * a description, so a filter on it must select peer 3's rejection alone.
 */
TEST_F(E2ERejectedNetworksTest, NeighborNameRegexSelectsSubsetOfPeers) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  addRoute("v4", "10.0.0.0", 8, kPeerAddr4, "11.0.0.2", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));
  ASSERT_EQ(2, walkRejected().size());

  const re2::RE2 matching("^rsw001");
  ASSERT_TRUE(matching.ok());
  EXPECT_EQ(1, walkRejected(&matching).size());

  const re2::RE2 nonMatching("^nosuchdevice");
  ASSERT_TRUE(nonMatching.ok());
  EXPECT_TRUE(walkRejected(&nonMatching).empty());
}

/*
 * policy_name_regex is the server-side replacement for the CLI's "crf"
 * subcommand. Drive it with the reason the engine actually produced, so the
 * test proves filtering works without pinning the engine's wording.
 */
TEST_F(E2ERejectedNetworksTest, PolicyNameRegexFiltersByRejectReason) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));

  const auto baseline = walkRejected();
  ASSERT_EQ(1, baseline.size());

  const re2::RE2 matching(re2::RE2::QuoteMeta(baseline[0].policyName));
  ASSERT_TRUE(matching.ok());
  EXPECT_EQ(1, walkRejected(nullptr, &matching).size());

  const re2::RE2 nonMatching("^Denied by SomeOtherPolicyThatDoesNotExist$");
  ASSERT_TRUE(nonMatching.ok());
  EXPECT_TRUE(walkRejected(nullptr, &nonMatching).empty());
}

/*
 * An explicit prefix list restricts the walk to those prefixes.
 */
TEST_F(E2ERejectedNetworksTest, PrefixFilterRestrictsResults) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix, "30.0.0.0/8"});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  addRoute("v4", "30.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));
  ASSERT_TRUE(
      verifyRouteNotInShadowRib(folly::IPAddress::createNetwork("30.0.0.0/8")));
  ASSERT_EQ(2, walkRejected().size());

  const std::set<TIpPrefix> onlyDenied{toTIpPrefix(kDeniedPrefix)};
  const auto filtered = walkRejected(nullptr, nullptr, onlyDenied);

  ASSERT_EQ(1, filtered.size());
  EXPECT_EQ(toTIpPrefix(kDeniedPrefix), filtered[0].prefix);
}

/*
 * The AFI filter excludes rejections from the other address family. Both
 * rejections here are IPv4, so asking for IPv6 must return nothing while
 * asking for IPv4 returns them.
 */
TEST_F(E2ERejectedNetworksTest, AfiFilterExcludesOtherFamily) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));

  EXPECT_EQ(1, walkRejected(nullptr, nullptr, {}, TBgpAfi::AFI_IPV4).size());
  EXPECT_TRUE(walkRejected(nullptr, nullptr, {}, TBgpAfi::AFI_IPV6).empty());
}

/*
 * The direction selects which Adj-RIB is walked. This route is denied by an
 * INGRESS policy, so INGRESS reports it and EGRESS -- reading the peer's
 * RIB-OUT, a different tree -- must not.
 *
 * BOTH is checked here too. It is representable on TDirectionFilter but not
 * servable by a walk that resolves against one Adj-RIB, so it must yield
 * nothing rather than one arbitrary side. The thrift handler refuses it
 * before this layer is reached; this pins the behavior for a caller that
 * bypasses that check.
 */
TEST_F(E2ERejectedNetworksTest, DirectionSelectsTheAdjRibWalked) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));

  EXPECT_EQ(1, walkRejected().size());
  EXPECT_TRUE(
      walkRejected(nullptr, nullptr, {}, std::nullopt, TDirectionFilter::EGRESS)
          .empty());
  EXPECT_TRUE(
      walkRejected(nullptr, nullptr, {}, std::nullopt, TDirectionFilter::BOTH)
          .empty());
}

/*
 * Explicit peer addresses bypass the name regex and select exactly those
 * peers, which is how a caller drills into one neighbor.
 */
TEST_F(E2ERejectedNetworksTest, ExplicitPeerListSelectsThosePeers) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  const auto all = peerManager_->resolveRejectedNetworkPeers(nullptr, {});
  ASSERT_EQ(3, all.size());

  const auto single =
      peerManager_->resolveRejectedNetworkPeers(nullptr, {kPeerAddr3.str()});
  ASSERT_EQ(1, single.size());
  EXPECT_EQ(kPeerAddr3, single[0].peerAddr);
  EXPECT_EQ(kDescription1, single[0].peerDescription);

  /* An address that is not a configured peer selects nothing. */
  EXPECT_TRUE(peerManager_->resolveRejectedNetworkPeers(nullptr, {"192.0.2.1"})
                  .empty());

  /* A malformed address is skipped rather than throwing. */
  EXPECT_TRUE(peerManager_->resolveRejectedNetworkPeers(nullptr, {"not-an-ip"})
                  .empty());
}

/*
 * A neighbor named twice in the explicit list is resolved once. `peers` comes
 * straight off the wire, so a repeat is a caller mistake rather than an
 * impossible state -- and without de-duplication 3/3 walks that neighbor twice
 * and reports every one of its rejections twice.
 */
TEST_F(E2ERejectedNetworksTest, DuplicatePeerAddressResolvesOnce) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));

  const auto peerAddr = kPeerAddr3.str();
  const auto resolved = peerManager_->resolveRejectedNetworkPeers(
      nullptr, {peerAddr, peerAddr, peerAddr});

  ASSERT_EQ(1, resolved.size());
  EXPECT_EQ(kPeerAddr3, resolved[0].peerAddr);
  /* Description still populated -- de-duplication keeps the first entry. */
  EXPECT_EQ(kDescription1, resolved[0].peerDescription);

  /* And so the rejection is reported once, not three times. */
  std::vector<RejectedNetwork> rejected;
  for (const auto& peerId : resolved) {
    const auto perPeer =
        peerManager_
            ->getRejectedNetworksForPeer(
                peerId,
                RejectedNetworksQuery{.direction = TDirectionFilter::INGRESS})
            .entries;
    rejected.insert(rejected.end(), perPeer.begin(), perPeer.end());
  }
  EXPECT_EQ(1, rejected.size());
}

/*
 * maxEntries bounds what one peer's walk lists without losing count of what it
 * rejected: the entry list stops at the cap and says so, while the per-policy
 * path count still covers every rejection. This is what keeps a deny-all
 * policy over a large RIB from allocating per route on the event base.
 */
TEST_F(E2ERejectedNetworksTest, MaxEntriesCapsEntriesButCountsEveryPath) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix, "30.0.0.0/8"});

  addRoute("v4", "10.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  addRoute("v4", "30.0.0.0", 8, kPeerAddr3, "11.0.0.1", "65001");
  ASSERT_TRUE(verifyRouteNotInShadowRib(
      folly::IPAddress::createNetwork(kDeniedPrefix)));
  ASSERT_TRUE(
      verifyRouteNotInShadowRib(folly::IPAddress::createNetwork("30.0.0.0/8")));

  const BgpPeerId peer3{kPeerAddr3, kPeerAddr3.asV4().toLongHBO()};
  const auto sumPaths = [](const RejectedNetworks& rejected) {
    int64_t total = 0;
    for (const auto& [_, count] : rejected.pathCountByPolicy) {
      total += count;
    }
    return total;
  };

  const auto uncapped = peerManager_->getRejectedNetworksForPeer(
      peer3, RejectedNetworksQuery{.direction = TDirectionFilter::INGRESS});
  EXPECT_EQ(2, uncapped.entries.size());
  EXPECT_EQ(2, sumPaths(uncapped));
  EXPECT_FALSE(uncapped.truncated);

  const auto capped = peerManager_->getRejectedNetworksForPeer(
      peer3,
      RejectedNetworksQuery{
          .direction = TDirectionFilter::INGRESS, .maxEntries = 1});
  EXPECT_EQ(1, capped.entries.size());
  EXPECT_EQ(2, sumPaths(capped));
  EXPECT_TRUE(capped.truncated);
}

} /* namespace facebook::bgp */
