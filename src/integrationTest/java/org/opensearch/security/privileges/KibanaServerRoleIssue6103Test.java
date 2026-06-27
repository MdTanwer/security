/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package org.opensearch.security.privileges;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import org.apache.commons.io.IOUtils;
import org.junit.Test;

import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.ResolvedIndices;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.security.privileges.actionlevel.RoleBasedActionPrivileges;
import org.opensearch.security.privileges.dlsfls.FieldMasking;
import org.opensearch.security.securityconf.DynamicConfigFactory;
import org.opensearch.security.securityconf.FlattenedActionGroups;
import org.opensearch.security.securityconf.impl.CType;
import org.opensearch.security.securityconf.impl.SecurityDynamicConfiguration;
import org.opensearch.security.securityconf.impl.v7.RoleV7;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isAllowed;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.isForbidden;
import static org.opensearch.security.privileges.PrivilegeEvaluatorResponseMatcher.missingPrivileges;
import static org.opensearch.security.util.MockIndexMetadataBuilder.indices;
import static org.opensearch.security.util.MockPrivilegeEvaluationContextBuilder.ctx;

/**
 * Regression test for https://github.com/opensearch-project/security/issues/6103
 */
public class KibanaServerRoleIssue6103Test {

    @Test
    public void kibanaServerRole_hasIndicesAdminGet_onCatchAllIndexPattern() throws Exception {
        RoleBasedActionPrivileges actionPrivileges = loadStaticActionPrivileges();

        PrivilegesEvaluatorResponse response = actionPrivileges.hasIndexPrivilege(
            ctx().roles("kibana_server").actionPrivileges(actionPrivileges).get(),
            Set.of("indices:admin/get"),
            ResolvedIndices.of("some-unrelated-index")
        );

        assertThat(response, isAllowed());
    }

    @Test
    public void kibanaServerRole_hasIndicesAdminGet_onKibanaIndex() throws Exception {
        RoleBasedActionPrivileges actionPrivileges = loadStaticActionPrivileges();

        PrivilegesEvaluatorResponse response = actionPrivileges.hasIndexPrivilege(
            ctx().roles("kibana_server").actionPrivileges(actionPrivileges).get(),
            Set.of("indices:admin/get"),
            ResolvedIndices.of(".kibana_1")
        );

        assertThat(response, isAllowed());
    }

    @Test
    public void kibanaServerRole_hasIndicesAdminGet_forAnyIndex_whenKibanaNotYetCreated() throws Exception {
        RoleBasedActionPrivileges actionPrivileges = loadStaticActionPrivileges();
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE).metadata(indices().build()).build();

        PrivilegesEvaluatorResponse response = actionPrivileges.hasIndexPrivilegeForAnyIndex(
            ctx().roles("kibana_server").actionPrivileges(actionPrivileges).clusterState(clusterState).get(),
            Set.of("indices:admin/get")
        );

        assertThat(response, isAllowed());
    }

    @Test
    public void kibanaServerRole_hasIndicesAdminGet_onDotKibanaAliasWhenExists() throws Exception {
        RoleBasedActionPrivileges actionPrivileges = loadStaticActionPrivileges();
        ClusterState clusterState = ClusterState.builder(ClusterState.EMPTY_STATE)
            .metadata(indices().index(".kibana_1").alias(".kibana").of(".kibana_1").build())
            .build();

        PrivilegesEvaluatorResponse response = actionPrivileges.hasIndexPrivilege(
            ctx().roles("kibana_server").actionPrivileges(actionPrivileges).clusterState(clusterState).get(),
            Set.of("indices:admin/get"),
            ResolvedIndices.of(".kibana")
        );

        assertThat(response, isAllowed());
    }

    @Test
    public void kibanaServerRole_cannotWriteUnrelatedIndex() throws Exception {
        RoleBasedActionPrivileges actionPrivileges = loadStaticActionPrivileges();

        PrivilegesEvaluatorResponse response = actionPrivileges.hasIndexPrivilege(
            ctx().roles("kibana_server").actionPrivileges(actionPrivileges).get(),
            Set.of("indices:data/write/index"),
            ResolvedIndices.of("some-unrelated-index")
        );

        assertThat(response, isForbidden());
        assertThat(response, missingPrivileges("indices:data/write/index"));
    }

    private static RoleBasedActionPrivileges loadStaticActionPrivileges() throws Exception {
        SecurityDynamicConfiguration<RoleV7> roles = SecurityDynamicConfiguration.fromYaml(
            testResource("/static_config/static_roles.yml"),
            CType.ROLES
        );
        FlattenedActionGroups actionGroups = new FlattenedActionGroups(
            SecurityDynamicConfiguration.fromYaml(testResource("/static_config/static_action_groups.yml"), CType.ACTIONGROUPS)
        );

        return new RoleBasedActionPrivileges(
            new CompiledRoles(roles, actionGroups, NamedXContentRegistry.EMPTY, FieldMasking.Config.DEFAULT, false),
            org.opensearch.security.privileges.actionlevel.RuntimeOptimizedActionPrivileges.SpecialIndexProtection.NONE,
            Settings.EMPTY,
            false
        );
    }

    private static String testResource(String fileName) throws IOException {
        InputStream in = DynamicConfigFactory.class.getResourceAsStream(fileName);

        if (in == null) {
            throw new FileNotFoundException("could not find " + fileName);
        }

        return IOUtils.toString(in, StandardCharsets.UTF_8);
    }
}
