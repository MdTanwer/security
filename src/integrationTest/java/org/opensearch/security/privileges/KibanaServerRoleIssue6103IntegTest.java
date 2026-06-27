/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.io.IOException;

import org.junit.ClassRule;
import org.junit.Test;

import org.opensearch.client.RestHighLevelClient;
import org.opensearch.client.indices.GetIndexRequest;
import org.opensearch.test.framework.TestSecurityConfig;
import org.opensearch.test.framework.cluster.ClusterManager;
import org.opensearch.test.framework.cluster.LocalCluster;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.opensearch.client.RequestOptions.DEFAULT;
import static org.opensearch.core.rest.RestStatus.FORBIDDEN;
import static org.opensearch.test.framework.TestSecurityConfig.AuthcDomain.AUTHC_HTTPBASIC_INTERNAL;
import static org.opensearch.test.framework.matcher.ExceptionMatcherAssert.assertThatThrownBy;
import static org.opensearch.test.framework.matcher.OpenSearchExceptionMatchers.statusException;

/**
 * End-to-end regression test for https://github.com/opensearch-project/security/issues/6103
 */
public class KibanaServerRoleIssue6103IntegTest {

    private static final TestSecurityConfig.User DASHBOARDS_SERVER_USER = new TestSecurityConfig.User("kibanaserver").password(
        "kibanaserver-secret"
    );

    /**
     * Mirrors the pre-fix catch-all permissions: alias management only, no {@code indices:admin/get}.
     */
    private static final TestSecurityConfig.Role LEGACY_DASHBOARDS_SERVER_ROLE = new TestSecurityConfig.Role("legacy_dashboards_server")
        .clusterPermissions(
            "cluster_composite_ops",
            "cluster_monitor",
            "indices:admin/index_template*",
            "indices:admin/template*",
            "indices:data/read/scroll*",
            "manage_point_in_time"
        )
        .indexPermissions("indices_all")
        .on(
            ".kibana",
            ".opensearch_dashboards",
            ".kibana-6",
            ".opensearch_dashboards-6",
            ".kibana_*",
            ".opensearch_dashboards_*",
            ".tasks",
            ".management-beats*"
        )
        .indexPermissions("indices:admin/aliases*")
        .on("*");

    private static final TestSecurityConfig.User LEGACY_DASHBOARDS_SERVER_USER = new TestSecurityConfig.User("legacy-kibanaserver")
        .password("legacy-kibanaserver-secret")
        .roles(LEGACY_DASHBOARDS_SERVER_ROLE);

    @ClassRule
    public static LocalCluster cluster = new LocalCluster.Builder().clusterManager(ClusterManager.SINGLENODE)
        .authc(AUTHC_HTTPBASIC_INTERNAL)
        .users(DASHBOARDS_SERVER_USER, LEGACY_DASHBOARDS_SERVER_USER)
        .rolesMapping(new TestSecurityConfig.RoleMapping("kibana_server").reserved(true).users(DASHBOARDS_SERVER_USER.getName()))
        .build();

    @Test
    public void kibanaServerUser_canCheckIfKibanaIndexExistsBeforeBootstrap() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(DASHBOARDS_SERVER_USER)) {
            boolean exists = client.indices().exists(new GetIndexRequest(".kibana"), DEFAULT);

            assertThat(exists, is(false));
        }
    }

    @Test
    public void legacyDashboardsServerRole_cannotCheckIfKibanaIndexExistsBeforeBootstrap() throws IOException {
        try (RestHighLevelClient client = cluster.getRestHighLevelClient(LEGACY_DASHBOARDS_SERVER_USER)) {
            assertThatThrownBy(() -> client.indices().exists(new GetIndexRequest(".kibana"), DEFAULT), statusException(FORBIDDEN));
        }
    }
}
