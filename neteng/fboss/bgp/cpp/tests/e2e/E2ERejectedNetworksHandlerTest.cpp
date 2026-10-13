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
 * E2E tests for the getRejectedNetworksSummary / getRejectedNetworksDetails
 * thrift handlers.
 *
 * E2ERejectedNetworksTest covers the AdjRib walk by calling PeerManagerBase
 * directly. That leaves the handler layer -- the direction mapping, the two
 * timeout-protected event base hops, and all of the response aggregation
 * (per-policy rollup, (prefix, policy) grouping, truncation) -- unexercised,
 * because the mock fixture in BgpServiceTest.cpp never runs the peer manager
 * event base, so any well-formed request there blocks for the full timeout.
 *
 * These tests drive the real handlers against a real running PeerManager, so
 * the aggregation and the hops are covered for real. Fixture shape follows
 * UpdateGroupPolicyReEvalE2EBase::setupComponentsWithBgpService.
 *
 * Mocked: FIB (TestFib), SessionManager (MockSessionManager)
 * Real: RIB, PeerManagerBase (running evb), AdjRib, PolicyManager, BgpServiceBB
 */

#include <gtest/gtest.h>

#include <chrono>
#include <memory>

#include <folly/IPAddress.h>
#include <folly/ScopeGuard.h>
#include <folly/coro/BlockingWait.h>
#include <folly/synchronization/Baton.h>

#include "neteng/fboss/bgp/cpp/BgpServiceBB.h"
#include "neteng/fboss/bgp/cpp/BgpServiceUtil.h"
#include "neteng/fboss/bgp/cpp/tests/e2e/E2ETestFixture.h"
#include "neteng/fboss/bgp/cpp/watchdog/Watchdog.h"

using facebook::neteng::fboss::bgp::thrift::TDirectionFilter;
using facebook::neteng::fboss::bgp::thrift::TRejectedNetworksRequest;
using facebook::neteng::fboss::bgp_attr::TBgpAfi;
using facebook::neteng::fboss::bgp_attr::TIpPrefix;

namespace facebook::bgp {

namespace {
constexpr auto kDeniedPrefix = "10.0.0.0/8";
constexpr auto kSecondDeniedPrefix = "12.0.0.0/8";
constexpr auto kThirdDeniedPrefix = "13.0.0.0/8";
} // namespace

class E2ERejectedNetworksHandlerTest : public E2ETestFixture {
 protected:
  /*
   * Stands up three peers behind an ingress policy denying `denied`, then a
   * BgpServiceBB sharing the fixture's ConfigManager so config versions stay
   * consistent with the PeerManager.
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

    watchdog_ = std::make_unique<Watchdog>(config_);
    bgpService_ = std::make_unique<BgpServiceBB>(
        *peerManager_,
        configManager_,
        *rib_,
        *watchdog_,
        /*nlWrapper=*/nullptr,
        /*enable_thrift_protection=*/false);
  }

  /* Denied on ingress, so the received direction is the one that reports it. */
  static TRejectedNetworksRequest receivedRequest() {
    TRejectedNetworksRequest request;
    request.direction() = TDirectionFilter::INGRESS;
    return request;
  }

  auto summary(const TRejectedNetworksRequest& request) {
    // @lint-ignore CLANGTIDY facebook-thrift-handler-direct-call
    return folly::coro::blockingWait(bgpService_->co_getRejectedNetworksSummary(
        std::make_unique<TRejectedNetworksRequest>(request)));
  }

  auto details(const TRejectedNetworksRequest& request) {
    // @lint-ignore CLANGTIDY facebook-thrift-handler-direct-call
    return folly::coro::blockingWait(bgpService_->co_getRejectedNetworksDetails(
        std::make_unique<TRejectedNetworksRequest>(request)));
  }

  /* Denies on peer 3 only; the other two peers advertise nothing. */
  void denyRouteOnPeer3(const std::string& prefix) {
    const auto network = folly::IPAddress::createNetwork(prefix);
    addRoute(
        "v4",
        network.first.str(),
        network.second,
        kPeerAddr3,
        "11.0.0.1",
        "65001");
    ASSERT_TRUE(verifyRouteNotInShadowRib(network));
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

  std::unique_ptr<Watchdog> watchdog_;
  std::unique_ptr<BgpServiceBB> bgpService_;
};

/*
 * The summary rolls a rejection up per policy and reports no per-prefix detail.
 * This is the whole point of the summary endpoint existing separately.
 */
TEST_F(E2ERejectedNetworksHandlerTest, SummaryReportsPerPolicyRollup) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});
  denyRouteOnPeer3(kDeniedPrefix);

  auto response = summary(receivedRequest());

  ASSERT_EQ(1, response->by_policy()->size());
  const auto& stats = response->by_policy()->begin()->second;
  EXPECT_EQ(1, folly::copy(stats.prefix_count().value()));
  EXPECT_EQ(1, folly::copy(stats.path_count().value()));
  EXPECT_EQ(1, folly::copy(stats.neighbor_count().value()));

  EXPECT_EQ(1, folly::copy(response->total_rejected_paths().value()));
  // Every peer the filters selected was walked, not just the denying one.
  EXPECT_EQ(3, folly::copy(response->neighbors_matched().value()));
  EXPECT_FALSE(folly::copy(response->truncated().value()));
}

/*
 * The details endpoint returns the same rollup plus one group per
 * (prefix, policy), naming the neighbor it applies to.
 */
TEST_F(E2ERejectedNetworksHandlerTest, DetailsReportsGroupPerPrefixAndPolicy) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});
  denyRouteOnPeer3(kDeniedPrefix);

  auto response = details(receivedRequest());

  ASSERT_EQ(1, response->groups()->size());
  const auto& group = response->groups()->at(0);
  EXPECT_EQ(toTIpPrefix(kDeniedPrefix), folly::copy(group.prefix().value()));
  EXPECT_FALSE(group.policy_name()->empty());
  ASSERT_EQ(1, group.neighbors()->size());
  EXPECT_EQ(kPeerAddr3.str(), *group.neighbors()->at(0).peer_addr());

  // Superset of the summary, so the rollup must be populated identically.
  EXPECT_EQ(1, response->by_policy()->size());
  EXPECT_EQ(1, folly::copy(response->total_rejected_paths().value()));
  EXPECT_EQ(3, folly::copy(response->neighbors_matched().value()));
  EXPECT_FALSE(folly::copy(response->truncated().value()));
}

/*
 * Pins which Adj-RIB each direction walks. The route here is denied by an
 * INGRESS policy, so INGRESS must report it and EGRESS must not. Swapping the
 * two arms in AdjRib::getRejectedNetworks fails this test; without it the
 * mapping is unverified, since the request default alone reaches only one arm.
 */
TEST_F(E2ERejectedNetworksHandlerTest, DirectionSelectsTheMatchingAdjRib) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});
  denyRouteOnPeer3(kDeniedPrefix);

  auto received = receivedRequest();
  EXPECT_EQ(1, folly::copy(details(received)->total_rejected_paths().value()));

  auto advertised = receivedRequest();
  advertised.direction() = TDirectionFilter::EGRESS;
  auto egressResponse = details(advertised);
  EXPECT_TRUE(egressResponse->groups()->empty());
  EXPECT_EQ(0, folly::copy(egressResponse->total_rejected_paths().value()));
  // The peers were still walked, so an empty result is not a filter miss.
  EXPECT_EQ(3, folly::copy(egressResponse->neighbors_matched().value()));
}

/*
 * BOTH cannot be served, since rejection resolves against one Adj-RIB per walk.
 */
TEST_F(E2ERejectedNetworksHandlerTest, BothDirectionIsRefused) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});
  denyRouteOnPeer3(kDeniedPrefix);

  auto request = receivedRequest();
  request.direction() = TDirectionFilter::BOTH;
  auto response = details(request);

  EXPECT_TRUE(response->groups()->empty());
  EXPECT_TRUE(response->by_policy()->empty());
  EXPECT_EQ(0, folly::copy(response->neighbors_matched().value()));
}

/*
 * max_groups caps the returned list and flags it, while the totals continue to
 * describe everything walked.
 */
TEST_F(E2ERejectedNetworksHandlerTest, MaxGroupsCapsListButNotTotals) {
  setUpWithPrefixDenyPolicy(
      {kDeniedPrefix, kSecondDeniedPrefix, kThirdDeniedPrefix});
  denyRouteOnPeer3(kDeniedPrefix);
  denyRouteOnPeer3(kSecondDeniedPrefix);
  denyRouteOnPeer3(kThirdDeniedPrefix);

  auto request = receivedRequest();
  request.max_groups() = 2;
  auto response = details(request);

  EXPECT_EQ(2, response->groups()->size());
  EXPECT_TRUE(folly::copy(response->truncated().value()));
  EXPECT_EQ(3, folly::copy(response->total_rejected_paths().value()));
  EXPECT_EQ(
      3,
      folly::copy(
          response->by_policy()->begin()->second.prefix_count().value()));
}

/*
 * A per-peer walk that times out ends the scan: that peer and every peer not
 * yet walked are reported as failed, and nothing more is queued behind the
 * wedged event base.
 *
 * Observed through elapsed time because every timed-out hop waits out the full
 * timeout: continuing past the first timeout would queue each remaining peer's
 * walk behind it and wait out three timeouts, never less. The queued work
 * itself is not observable -- the peer manager keeps posting its own work to
 * the same event base while it is wedged.
 */
TEST_F(E2ERejectedNetworksHandlerTest, WalkTimeoutAbandonsRemainingPeers) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});
  const auto peerIds = peerManager_->resolveRejectedNetworkPeers(nullptr, {});
  ASSERT_EQ(3, peerIds.size());

  auto& evb = peerManager_->getEventBase();
  auto wedged = std::make_shared<folly::Baton<>>();
  auto release = std::make_shared<folly::Baton<>>();
  SCOPE_EXIT {
    release->post();
  };
  evb.runInEventBaseThread([wedged, release] {
    wedged->post();
    release->wait();
  });
  wedged->wait();

  constexpr std::chrono::milliseconds kTimeout{500};
  RejectedNetworksAccumulator accumulator;
  const auto start = std::chrono::steady_clock::now();
  folly::coro::blockingWait(co_walkRejectedNetworkPeers(
      *peerManager_,
      peerIds,
      RejectedNetworksWalk{.direction = TDirectionFilter::INGRESS},
      accumulator,
      kTimeout));
  const auto elapsed = std::chrono::steady_clock::now() - start;

  EXPECT_LT(elapsed, 3 * kTimeout);
  const auto response = accumulator.buildSummary(/*neighborsMatched=*/3);
  EXPECT_EQ(3, folly::copy(response.peers_failed().value()));
}

/*
 * The server-side caps (kMaxTrackedRejectedGroups,
 * kMaxTrackedRejectedNeighbors) are construction parameters of
 * RejectedNetworksAccumulator, not something a request can influence, so they
 * are driven directly in tests:bgp_service_util_test --
 * RejectedNetworksAccumulatorTest. The handler path above covers everything
 * the caller can reach.
 */

/*
 * neighbors_matched reflects the filters, letting a caller tell "nothing was
 * rejected" apart from "the regex matched no neighbor". peers_failed stays 0
 * on a healthy walk, so a non-zero value is a real "results are incomplete"
 * signal rather than noise.
 */
TEST_F(E2ERejectedNetworksHandlerTest, NeighborNameRegexNarrowsPeersWalked) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});
  denyRouteOnPeer3(kDeniedPrefix);

  auto request = receivedRequest();
  request.neighbor_name_regex() = kDescription1;
  auto matched = summary(request);
  EXPECT_EQ(1, folly::copy(matched->neighbors_matched().value()));
  EXPECT_EQ(1, folly::copy(matched->total_rejected_paths().value()));
  EXPECT_EQ(0, folly::copy(matched->peers_failed().value()));

  auto missRequest = receivedRequest();
  missRequest.neighbor_name_regex() = "^no-such-neighbor$";
  auto missed = summary(missRequest);
  EXPECT_EQ(0, folly::copy(missed->neighbors_matched().value()));
  EXPECT_EQ(0, folly::copy(missed->peers_failed().value()));
  EXPECT_TRUE(missed->by_policy()->empty());
}

/*
 * A prefix filter restricts the walk without disturbing the rollup shape.
 */
TEST_F(E2ERejectedNetworksHandlerTest, PrefixFilterRestrictsResults) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix, kSecondDeniedPrefix});
  denyRouteOnPeer3(kDeniedPrefix);
  denyRouteOnPeer3(kSecondDeniedPrefix);

  auto request = receivedRequest();
  request.prefixes() = {toTIpPrefix(kSecondDeniedPrefix)};
  auto response = details(request);

  ASSERT_EQ(1, response->groups()->size());
  EXPECT_EQ(
      toTIpPrefix(kSecondDeniedPrefix),
      folly::copy(response->groups()->at(0).prefix().value()));
  EXPECT_EQ(1, folly::copy(response->total_rejected_paths().value()));
}

/*
 * Nothing denied is an empty success, not an error, on both endpoints.
 */
TEST_F(E2ERejectedNetworksHandlerTest, NoRejectionsReturnsEmptySuccess) {
  setUpWithPrefixDenyPolicy({kDeniedPrefix});

  auto detailsResponse = details(receivedRequest());
  EXPECT_TRUE(detailsResponse->groups()->empty());
  EXPECT_TRUE(detailsResponse->by_policy()->empty());
  EXPECT_EQ(0, folly::copy(detailsResponse->total_rejected_paths().value()));
  EXPECT_EQ(3, folly::copy(detailsResponse->neighbors_matched().value()));

  auto summaryResponse = summary(receivedRequest());
  EXPECT_TRUE(summaryResponse->by_policy()->empty());
  EXPECT_EQ(3, folly::copy(summaryResponse->neighbors_matched().value()));
}

} // namespace facebook::bgp
