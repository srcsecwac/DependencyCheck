/*
 * This file is part of dependency-check-core.
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
 *
 * Copyright (c) 2017 Jeremy Long. All Rights Reserved.
 */
package org.owasp.dependencycheck.data.central;

import java.util.List;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jeremy long
 */
public class CentralDatabaseCache implements CentralCache {

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CentralDatabaseCache.class);

    /**
     * The configured settings.
     */
    private final Settings settings;
    /**
     * A reference to the database.
     */
    private final CveDB db;
    /**
     * Creates a Cache for the Central Search for the given repository URL.
     *
     * @param settings the configured settings
     * @param db a reference to the database
     */
    public CentralDatabaseCache(Settings settings, CveDB db) {
        this.settings  = settings;
        this.db  = db;
    }
    
    @Override
    public List<MavenArtifact> searchSha1(String sha1) {
        return db.getCentralCache(sha1);
    }
    @Override
    public void cacheData(String sha1, MavenArtifact ma) {
        db.addCentralCache(sha1, ma.getGroupId(), ma.getArtifactId(), ma.getVersion(),ma.getArtifactUrl(),ma.getPomUrl());
    }
    @Override
    public void removeCacheEntries() {
        final int validForDays = settings.getInt(Settings.KEYS.ANALYZER_CENTRAL_CACHE_VALID_DAYS, 90);
        db.clearCentralCache(validForDays);
    }
}
