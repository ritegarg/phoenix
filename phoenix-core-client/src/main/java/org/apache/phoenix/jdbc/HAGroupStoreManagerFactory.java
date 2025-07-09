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

import org.apache.commons.lang3.StringUtils;
import org.apache.hadoop.conf.Configuration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

import static org.apache.phoenix.jdbc.PhoenixHAAdmin.getLocalZkUrl;

/**
 * Factory class for creating HAGroupStoreManager instances.
 */
public class HAGroupStoreManagerFactory {

    private static final Logger LOGGER = LoggerFactory.getLogger(HAGroupStoreManagerFactory.class);

    public static final String HA_GROUP_STORE_MANAGER_IMPL_CLASS_KEY = "phoenix.ha.groupstore.manager.impl.class";

    private static final String DEFAULT_IMPL_CLASS = "HAGroupStoreManagerV1Impl";

    private static volatile Map<String, HAGroupStoreManager> INSTANCES = new ConcurrentHashMap<>();

    /**
     * Creates/gets an instance of HAGroupStoreManager.
     * Returns empty optional if configuration zk url is null/invalid.
     * Provides unique instance for each ZK URL
     *
     * @param conf configuration
     * @return HAGroupStoreManager instance
     */
    public static Optional<HAGroupStoreManager> getInstance(Configuration conf) {
        String zkUrl = null;
        try {
            zkUrl = getLocalZkUrl(conf);
        } catch (Exception e) {
            LOGGER.error("Error getting local ZK URL", e);
            return Optional.empty();
        }
        if (StringUtils.isBlank(zkUrl)) {
            return Optional.empty();
        }
        HAGroupStoreManager result = INSTANCES.get(zkUrl);
        if (result == null) {
            synchronized (HAGroupStoreManagerFactory.class) {
                result = INSTANCES.get(zkUrl);
                if (result == null) {
                    result = createInstance(conf);
                    if (result != null) {
                        INSTANCES.put(zkUrl, result);
                    }
                }
            }
        }
        return Optional.ofNullable(result);
    }

    private static HAGroupStoreManager createInstance(Configuration conf) {
        String implClassName = conf.get(HA_GROUP_STORE_MANAGER_IMPL_CLASS_KEY, DEFAULT_IMPL_CLASS);

        switch (implClassName) {
            case "HAGroupStoreManagerImpl":
                return new HAGroupStoreManagerImpl(conf);

            case "HAGroupStoreManagerV1Impl":
                return new HAGroupStoreManagerV1Impl(conf);

            default:
                LOGGER.error("Unknown implementation for HAGroupStoreManager, returning null: {}", implClassName);
                return null;
        }
    }
}