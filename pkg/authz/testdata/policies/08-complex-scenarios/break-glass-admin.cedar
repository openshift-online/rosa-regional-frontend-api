forbid(
  ?principal,
  action in [ROSA::Action::"CreateCluster", ROSA::Action::"DeleteCluster", ROSA::Action::"DescribeCluster", ROSA::Action::"ListClusters", ROSA::Action::"UpdateCluster", ROSA::Action::"UpdateClusterConfig", ROSA::Action::"UpdateClusterVersion", ROSA::Action::"CreateNodePool", ROSA::Action::"DeleteNodePool", ROSA::Action::"DescribeNodePool", ROSA::Action::"ListNodePools", ROSA::Action::"UpdateNodePool", ROSA::Action::"ScaleNodePool", ROSA::Action::"CreateAccessEntry", ROSA::Action::"DeleteAccessEntry", ROSA::Action::"DescribeAccessEntry", ROSA::Action::"ListAccessEntries", ROSA::Action::"UpdateAccessEntry", ROSA::Action::"TagResource", ROSA::Action::"UntagResource", ROSA::Action::"ListTagsForResource", ROSA::Action::"ListAccessPolicies"],
  resource
)
when { context.mfaPresent == "false" };

forbid(
  ?principal,
  action in [ROSA::Action::"DeleteCluster", ROSA::Action::"DeleteNodePool", ROSA::Action::"DeleteAccessEntry"],
  resource
)
unless { context.sourceIp like "10.*" || context.sourceIp like "192.168.1.*" };

permit(
  ?principal,
  action in [ROSA::Action::"CreateCluster", ROSA::Action::"DeleteCluster", ROSA::Action::"DescribeCluster", ROSA::Action::"ListClusters", ROSA::Action::"UpdateCluster", ROSA::Action::"UpdateClusterConfig", ROSA::Action::"UpdateClusterVersion", ROSA::Action::"CreateNodePool", ROSA::Action::"DeleteNodePool", ROSA::Action::"DescribeNodePool", ROSA::Action::"ListNodePools", ROSA::Action::"UpdateNodePool", ROSA::Action::"ScaleNodePool", ROSA::Action::"CreateAccessEntry", ROSA::Action::"DeleteAccessEntry", ROSA::Action::"DescribeAccessEntry", ROSA::Action::"ListAccessEntries", ROSA::Action::"UpdateAccessEntry", ROSA::Action::"TagResource", ROSA::Action::"UntagResource", ROSA::Action::"ListTagsForResource", ROSA::Action::"ListAccessPolicies"],
  resource
);
