permit(
  ?principal,
  action == ROSA::Action::"CreateCluster",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"DeleteCluster",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"DescribeCluster",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"ListClusters",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"UpdateCluster",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"UpdateClusterConfig",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"UpdateClusterVersion",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"CreateNodePool",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"DeleteNodePool",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"DescribeNodePool",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"ListNodePools",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"UpdateNodePool",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"ScaleNodePool",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"CreateAccessEntry",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"DeleteAccessEntry",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"DescribeAccessEntry",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"ListAccessEntries",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"UpdateAccessEntry",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"TagResource",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"UntagResource",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"ListTagsForResource",
  resource
);
permit(
  ?principal,
  action == ROSA::Action::"ListAccessPolicies",
  resource
);
