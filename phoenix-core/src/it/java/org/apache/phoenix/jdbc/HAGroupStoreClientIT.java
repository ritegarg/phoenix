/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.phoenix.jdbc;

import org.apache.curator.utils.ZKPaths;
import org.apache.phoenix.end2end.NeedsOwnMiniClusterTest;
import org.apache.phoenix.query.BaseTest;
import org.apache.phoenix.thirdparty.com.google.common.collect.Maps;
import org.apache.phoenix.util.ReadOnlyProps;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.experimental.categories.Category;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.apache.phoenix.jdbc.PhoenixHAAdmin.toPath;
import static org.junit.Assert.assertThrows;

/**
 * Integration tests for {@link HAGroupStoreClient}
 */
@Category(NeedsOwnMiniClusterTest.class)
public class HAGroupStoreClientIT extends BaseTest {

    private final PhoenixHAAdmin haAdmin = new PhoenixHAAdmin(config);
    private static final Long ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS = 1000L;

    @BeforeClass
    public static synchronized void doSetup() throws Exception {
        Map<String, String> props = Maps.newHashMapWithExpectedSize(1);
        setUpTestDriver(new ReadOnlyProps(props.entrySet().iterator()));
    }

    @Before
    public void before() throws Exception {
        // Clean up all the existing CRRs
        List<ClusterRoleRecord> crrs = haAdmin.listAllClusterRoleRecordsOnZookeeper();
        for (ClusterRoleRecord crr : crrs) {
            haAdmin.getCurator().delete().forPath(toPath(crr.getHaGroupName()));
        }
    }

    @Test
    public void testHACacheWithSingleCRR() throws Exception {
        HAGroupStoreClient haGroupStoreClient = HAGroupStoreClient.getInstance(config);
        ClusterRoleRecord crr = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        haAdmin.createOrUpdateDataOnZookeeper(crr);
        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 1;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).isEmpty();

        // Now Update CRR so that current cluster has state ACTIVE_TO_STANDBY
        crr = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 2L);
        haAdmin.createOrUpdateDataOnZookeeper(crr);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        // Check that now the cluster should be in ActiveToStandby
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).isEmpty();
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).size() == 1;


        // Change it back to ACTIVE so that cluster is not in ACTIVE_TO_STANDBY state
        crr = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 3L);
        haAdmin.createOrUpdateDataOnZookeeper(crr);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 1;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).isEmpty();


        // Change it again to ACTIVE_TO_STANDBY so that we can validate watcher works repeatedly
        crr = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 4L);
        haAdmin.createOrUpdateDataOnZookeeper(crr);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).isEmpty();
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).size() == 1;


        // Change peer cluster to ACTIVE_TO_STANDBY so that we can still process mutation on this cluster
        crr = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY, 5L);
        haAdmin.createOrUpdateDataOnZookeeper(crr);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 1;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).isEmpty();
    }


    @Test
    public void testHACacheWithMultipleCRRs() throws Exception {
        HAGroupStoreClient haGroupStoreClient = HAGroupStoreClient.getInstance(config);
        // Setup initial CRRs
        ClusterRoleRecord crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        ClusterRoleRecord crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 2;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).isEmpty();

        // Now Update CRR so that current cluster has state ACTIVE_TO_STANDBY for only 1 crr
        crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 2L);
        crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 2L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        // Check that now the cluster should be in ActiveToStandby
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 1;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).size() == 1;


        // Change it back to ACTIVE so that cluster is not in ACTIVE_TO_STANDBY state
        crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 3L);
        crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 3L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 2;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).isEmpty();


        // Change other crr to ACTIVE_TO_STANDBY and one in ACTIVE state so that we can validate watcher works repeatedly
        crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 4L);
        crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 4L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 1;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).size() == 1;


        // Change peer cluster to ACTIVE_TO_STANDBY so that we can still process mutation on this cluster
        crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY, 5L);
        crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY, 5L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 2;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).isEmpty();
    }

    @Test
    public void testMultiThreadedAccessToHACache() throws Exception {
        HAGroupStoreClient haGroupStoreClient = HAGroupStoreClient.getInstance(config);
        // Setup initial CRRs
        ClusterRoleRecord crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        ClusterRoleRecord crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);

        int threadCount = 10;
        final CountDownLatch latch = new CountDownLatch(threadCount);
        ExecutorService executor = Executors.newFixedThreadPool(threadCount);
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 2;
                    assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).isEmpty();
                    latch.countDown();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
        assert latch.await(10, TimeUnit.SECONDS);

        // Update CRRs
        crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 2L);
        crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 2L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);

        final CountDownLatch latch2 = new CountDownLatch(threadCount);
        executor = Executors.newFixedThreadPool(threadCount);
        for (int i = 0; i < threadCount; i++) {
            executor.submit(() -> {
                try {
                    assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 1;
                    assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).size() == 1;
                    latch2.countDown();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            });
        }
        assert latch2.await(10, TimeUnit.SECONDS);
    }

    @Test
    public void testHACacheWithRootPathDeletion() throws Exception {
        HAGroupStoreClient haGroupStoreClient = HAGroupStoreClient.getInstance(config);
        ClusterRoleRecord crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        ClusterRoleRecord crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);
        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 1;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).size() == 1;

        haAdmin.getCurator().delete().deletingChildrenIfNeeded().forPath(ZKPaths.PATH_SEPARATOR);
        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).isEmpty();
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).isEmpty();


        crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 2L);
        crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 2L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);
        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 1;
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE_TO_STANDBY).size() == 1;
    }

    @Test
    public void testThrowsExceptionWithZKDisconnectionAndThenConnection() throws Exception {
        HAGroupStoreClient haGroupStoreClient = HAGroupStoreClient.getInstance(config);
        // Setup initial CRRs
        ClusterRoleRecord crr1 = new ClusterRoleRecord("failover",
                HighAvailabilityPolicy.FAILOVER, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        ClusterRoleRecord crr2 = new ClusterRoleRecord("parallel",
                HighAvailabilityPolicy.PARALLEL, haAdmin.getZkUrl(), ClusterRoleRecord.ClusterRole.ACTIVE,
                "random-zk-url", ClusterRoleRecord.ClusterRole.STANDBY, 1L);
        haAdmin.createOrUpdateDataOnZookeeper(crr1);
        haAdmin.createOrUpdateDataOnZookeeper(crr2);

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 2;

        // Shutdown the ZK Cluster to simulate CONNECTION_SUSPENDED event
        utility.shutdownMiniZKCluster();

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        //Check that HAGroupStoreClient instance is not healthy and throws IOException
        assertThrows(IOException.class, () -> haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE));

        // Start ZK on the same port to simulate CONNECTION_RECONNECTED event
        utility.startMiniZKCluster(1,Integer.parseInt(getZKClientPort(config)));

        Thread.sleep(ZK_CURATOR_EVENT_PROPAGATION_TIMEOUT_MS);
        //Check that HAGroupStoreClient instance is back to healthy and provides correct response
        assert haGroupStoreClient.getCRRsByClusterRole(ClusterRoleRecord.ClusterRole.ACTIVE).size() == 2;
    }
}
