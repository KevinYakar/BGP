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

#pragma once

#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <fmt/format.h>
#include <folly/container/F14Map.h>
#include <folly/container/F14Set.h>
#include <re2/re2.h>
#include <thrift/lib/cpp2/op/Get.h>
#include "configerator/structs/neteng/bgp_policy/thrift/gen-cpp2/rib_policy_types.h"
#include "configerator/structs/neteng/fboss/bgp/gen-cpp2/bgp_config_types.h"
#include "neteng/fboss/bgp/cpp/common/BgpPath.h"
#include "neteng/fboss/bgp/cpp/common/Consts.h"
#include "neteng/fboss/bgp/cpp/common/IpPrefixUtils.h"
#include "neteng/fboss/bgp/cpp/config/Config.h"
#include "neteng/fboss/bgp/cpp/lib/BgpStructs.h"
#include "neteng/fboss/bgp/cpp/policy/PolicyManager.h"
#include "neteng/fboss/bgp/if/gen-cpp2/bgp_thrift_types.h"

namespace facebook::bgp {

/**
 * Type alias for peer-to-policy map used by PeerManagerBase.
 * Maps peer address string -> direction -> optional policy name.
 * - std::nullopt means "clear/unset this policy"
 * - A value means "set to this policy name"
 */
using PeerToPolicyMap = folly::F14FastMap<
    std::string,
    folly::F14FastMap<bgp_policy::DIRECTION, std::optional<std::string>>>;

/**
 * Error codes for peer group configuration validation.
 */
enum class PeerGroupValidationResult {
  SUCCESS = 0,
  PEER_GROUP_NOT_FOUND = 1,
  IPV4_AFI_MISMATCH = 2,
  IPV6_AFI_MISMATCH = 3,
};

/**
 * Error codes for policy validation in setPeersPolicy and setPeerGroupsPolicy
 * APIs.
 */
enum class PolicyValidationResult {
  SUCCESS = 0,
  PEER_NOT_FOUND = 1,
  PEER_GROUP_NOT_FOUND = 2,
  POLICY_NOT_FOUND = 3,
  INTERNAL_ERROR = 4,
};

// default group
constexpr auto kDefaultPathGroup = "default";

constexpr auto kUpdateGroupEgressFilterError =
    "Failed to apply route filter policy: egress route filters are not "
    "supported when update groups are enabled";

/*
 * Used in getRibEntries grouping to indicate a path is selected as part of
 * bestpath/ECMP vs when it is not (in that case it will be grouped
 * under "default").
 */
constexpr auto kBestPathGroup = "best";
constexpr auto kMultiPathGroup = "multiPaths";

std::string TIpPrefixToString(const neteng::fboss::bgp_attr::TIpPrefix& prefix);

/**
 * Utility method to create CIDRNetwork from TIpPrefix
 */
folly::CIDRNetwork tIpPrefixToNetwork(
    const neteng::fboss::bgp_attr::TIpPrefix& prefix);

/**
 * Utility method to create TAsPathSeg from BgpAttrAsPathSegmentC
 */
neteng::fboss::bgp_attr::TAsPathSeg createTAsPathSeg(
    const nettools::bgplib::BgpAttrAsPathSegmentC& path);

/**
 * Utility method to create TBgpPath from BgpPath and prefix of
 * CIDRNetwork type
 */
neteng::fboss::bgp::thrift::TBgpPath createTBgpPath(
    const facebook::bgp::BgpPath& attr);

/**
 * Utility method to convert a deduplicated EXTENDED COMMUNITIES container to
 * its thrift representation. Shared by createTBgpPath and the canonical RIB
 * encoder (which interns ext-communities by pointer and rebuilds the value
 * here at snapshot time).
 */
std::vector<neteng::fboss::bgp::thrift::TBgpExtCommunity> createTExtCommunities(
    const nettools::bgplib::BgpAttrExtCommunitiesC& extCommunities);

/**
 * Utility function to set TResult with success status and optional error
 * message
 */
void setTResult(
    neteng::fboss::bgp::thrift::TResult& result,
    bool success,
    const std::optional<std::string>& errorMessage = std::nullopt);

/**
 * Validates peer group configuration in route filter policy.
 *
 * @return PeerGroupValidationResult::SUCCESS if validation passes,
 *         specific error code if validation fails
 */
PeerGroupValidationResult isPeerGroupConfigValid(
    const rib_policy::TRouteFilterPolicy& policy,
    const folly::F14NodeMap<std::string, thrift::PeerGroup>& peerGroups);

/**
 * Validates peer group configuration in route filter policy for Thrift API
 * usage. Calls the string version and populates TResult accordingly.
 */
void validatePeerGroupConfigInPolicy(
    neteng::fboss::bgp::thrift::TResult& result,
    const rib_policy::TRouteFilterPolicy& policy,
    const folly::F14NodeMap<std::string, thrift::PeerGroup>& peerGroups);

/**
 * Validates whether a route filter policy is supported with update groups.
 */
void validateUpdateGroupRouteFilterPolicy(
    neteng::fboss::bgp::thrift::TResult& result,
    const rib_policy::TRouteFilterPolicy& policy,
    const Config& config);

/**
 * Validates peers and their associated policies for setPeersPolicy API.
 *
 * @param peersPolicy Map from peer address to direction-to-policy mapping
 * @param config BGP configuration for peer existence validation
 * @param policyManager Policy manager for policy existence validation
 * @return PolicyValidationResult indicating success or specific error
 */
PolicyValidationResult validatePeersAndPolicies(
    const std::map<
        std::string,
        std::map<facebook::bgp::bgp_policy::DIRECTION, std::string>>&
        peersPolicy,
    const Config& config,
    const std::shared_ptr<PolicyManager>& policyManager);

/**
 * Validates peer groups and their associated policies for setPeerGroupsPolicy
 * API.
 *
 * @param peerGroupsPolicy Map from peer group name to direction-to-policy
 * mapping
 * @param config BGP configuration for peer group existence validation
 * @param policyManager Policy manager for policy existence validation
 * @return PolicyValidationResult indicating success or specific error
 */
PolicyValidationResult validatePeerGroupsAndPolicies(
    const std::map<
        std::string,
        std::map<facebook::bgp::bgp_policy::DIRECTION, std::string>>&
        peerGroupsPolicy,
    const Config& config,
    const std::shared_ptr<PolicyManager>& policyManager);

/**
 * Validates that all policies in directionToPolicy map exist in policy manager
 * @param directionToPolicy Map from direction to policy name
 * @param policyManager Policy manager for policy existence validation
 * @return PolicyValidationResult indicating success or specific error
 */
PolicyValidationResult validateDirectionToPolicyMap(
    const std::map<facebook::bgp::bgp_policy::DIRECTION, std::string>&
        directionToPolicy,
    const std::shared_ptr<PolicyManager>& policyManager);

/**
 * Resolve effective per-peer policies from Config::getPeerToConfig().
 * Iterates peerToConfig in a single pass, includes peers for which the
 * filter predicate returns true. Returns both directions for each peer
 * using std::optional semantics:
 * - std::nullopt means "clear/unset this policy"
 * - A value means "set to this policy name"
 */
std::unique_ptr<PeerToPolicyMap> resolveEffectivePeerPolicies(
    const Config& config,
    const std::function<bool(const folly::IPAddress&, const BgpPeerConfig&)>&
        filter);

/**
 * Returns the names of all fields set on the peer that are not in
 * allowedFields. Returns an empty vector if only allowed fields are present.
 */
std::vector<std::string> getUnsupportedBgpPeerFields(
    const thrift::BgpPeer& peer,
    const folly::F14FastSet<std::string_view>& allowedFields);

/**
 * Compiles an optional RE2 filter into `out`. An empty pattern is not a
 * filter, so it leaves `out` null and succeeds. Returns false when the caller
 * supplied a pattern that does not compile, so the handler can fail the
 * request rather than silently matching everything.
 */
bool compileOptionalRegex(
    const std::string& pattern,
    std::shared_ptr<re2::RE2>& out,
    std::string_view what);

/**
 * Memory bounds for RejectedNetworksAccumulator. Each is independent of the
 * others, so every allocation the accumulator makes is bounded on its own.
 */
struct RejectedNetworksLimits {
  /*
   * Distinct (prefix, policy) keys tracked, which is what prefix_count counts.
   * Keys are cheap -- no neighbor list -- so this can exceed maxGroups.
   */
  size_t maxTrackedKeys{kMaxTrackedRejectedGroups};
  /* Groups built for the details response. 0 builds none, for the summary. */
  size_t maxGroups{kMaxTrackedRejectedGroups};
  /* Neighbor entries across all groups. */
  size_t maxNeighbors{kMaxTrackedRejectedNeighbors};
};

/**
 * Accumulates policy rejections across peers into the getRejectedNetworks
 * thrift responses.
 *
 * Groups are keyed by (prefix, policy) and each records the neighbors that
 * rejected it. Peers are fed one at a time via setCurrentPeer(), so a repeat
 * of the current peer within a group can only be the immediately preceding
 * entry, and de-duplication is a back() comparison rather than a per-group
 * set.
 *
 * Past maxTrackedKeys the accumulator stops tracking new keys entirely and
 * both responses report truncated. total_rejected_paths and the by_policy
 * path_count / neighbor_count need no per-key state and stay exact;
 * prefix_count stops at the cap and is a lower bound. Keeping it exact would
 * mean holding every distinct key, which grows with RIB size -- the
 * allocation the cap exists to bound.
 *
 * maxGroups and maxNeighbors only shape the details breakdown: hitting them
 * truncates the details response, never the summary, and leaves prefix_count
 * exact.
 */
class RejectedNetworksAccumulator {
 public:
  explicit RejectedNetworksAccumulator(RejectedNetworksLimits limits = {})
      : limits_{limits} {}

  /* Every subsequent addRejected*() is attributed to this neighbor. */
  void setCurrentPeer(std::string peerAddr, std::string description);

  /*
   * Neighbors counted in neighbors_matched whose walk did not complete.
   * Surfaced as peers_failed so a caller can tell an empty result apart from
   * an incomplete one.
   */
  void addFailedPeers(int32_t count);

  /* `count` rejected paths by `policyName` on the current peer. */
  void addRejectedPaths(const std::string& policyName, int64_t count);

  /*
   * One rejected (prefix, policy) on the current peer, for prefix_count and
   * the details breakdown. Path counting is addRejectedPaths()'s job, so a
   * peer's walk may list fewer prefixes than it counted paths.
   */
  void addRejectedPrefix(
      const neteng::fboss::bgp_attr::TIpPrefix& prefix,
      const std::string& policyName);

  /*
   * A peer's walk counted rejections it did not list, so prefix_count may
   * have missed keys. Truncates both responses, like the key cap.
   */
  void markTruncated();

  neteng::fboss::bgp::thrift::TRejectedNetworksSummaryResponse buildSummary(
      int32_t neighborsMatched);

  neteng::fboss::bgp::thrift::TRejectedNetworksDetailsResponse buildDetails(
      int32_t neighborsMatched);

 private:
  void addCurrentPeerTo(
      neteng::fboss::bgp::thrift::TRejectedPrefixGroup& group);

  /* nullopt for a key tracked for prefix_count without a group behind it. */
  std::map<
      std::pair<neteng::fboss::bgp_attr::TIpPrefix, std::string>,
      std::optional<size_t>>
      keyIndex_;
  std::vector<neteng::fboss::bgp::thrift::TRejectedPrefixGroup> groups_;
  std::map<std::string, neteng::fboss::bgp::thrift::TRejectedPolicyStats>
      byPolicy_;
  std::map<std::string, std::set<std::string>> policyPeers_;
  std::string peerAddr_;
  std::string description_;
  RejectedNetworksLimits limits_;
  size_t neighborEntries_{0};
  int64_t totalPaths_{0};
  int32_t peersFailed_{0};
  /* prefix_count is a lower bound; truncates both responses. */
  bool keysTruncated_{false};
  /* The groups breakdown is partial; truncates only the details response. */
  bool groupsTruncated_{false};
};

} // namespace facebook::bgp
