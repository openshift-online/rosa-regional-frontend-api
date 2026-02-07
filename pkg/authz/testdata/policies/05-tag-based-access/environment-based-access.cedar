permit(
  ?principal,
  action in [ROSA::Action::"CreateCluster", ROSA::Action::"DeleteCluster", ROSA::Action::"DescribeCluster", ROSA::Action::"ListClusters", ROSA::Action::"UpdateCluster", ROSA::Action::"UpdateClusterConfig", ROSA::Action::"UpdateClusterVersion", ROSA::Action::"CreateNodePool", ROSA::Action::"DeleteNodePool", ROSA::Action::"DescribeNodePool", ROSA::Action::"ListNodePools", ROSA::Action::"UpdateNodePool", ROSA::Action::"ScaleNodePool", ROSA::Action::"CreateAccessEntry", ROSA::Action::"DeleteAccessEntry", ROSA::Action::"DescribeAccessEntry", ROSA::Action::"ListAccessEntries", ROSA::Action::"UpdateAccessEntry", ROSA::Action::"TagResource", ROSA::Action::"UntagResource", ROSA::Action::"ListTagsForResource", ROSA::Action::"ListAccessPolicies"],
  resource
)
when { resource.tags["Environment"] == "development" };

permit(
  ?principal,
  action in [ROSA::Action::"DescribeCluster", ROSA::Action::"DescribeNodePool", ROSA::Action::"DescribeAccessEntry", ROSA::Action::"ListClusters", ROSA::Action::"ListNodePools", ROSA::Action::"ListAccessEntries", ROSA::Action::"ListAccessPolicies", ROSA::Action::"ListTagsForResource"],
  resource
)
when { resource.tags["Environment"] == "production" };

permit(
  ?principal,
  action in [ROSA::Action::"ListClusters", ROSA::Action::"ListAccessPolicies"],
  resource
);
