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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import org.joda.time.Instant;
import java.util.ArrayList;
import java.util.List;
import org.apache.commons.io.FileUtils;
import org.joda.time.Interval;
import org.owasp.dependencycheck.data.nexus.MavenArtifact;
import org.owasp.dependencycheck.data.nvdcve.CveDB;
import org.owasp.dependencycheck.utils.Settings;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 *
 * @author jeremy long
 */
public class CentralDiskCache implements CentralCache {

    /**
     * Used for logging.
     */
    private static final Logger LOGGER = LoggerFactory.getLogger(CentralDiskCache.class);

    /**
     * The configured settings.
     */
    private final Settings settings;
    /**
     * A reference to the database.
     */
    private final File cache;
    private final long validFor;

    /**
     * Creates a Cache for the Central Search for the given repository URL.
     *
     * @param settings the configured settings
     * @param db a reference to the database
     * @throws CacheException thrown if the cache directory cannot be found or
     * created
     */
    public CentralDiskCache(Settings settings, CveDB db) throws CacheException {
        this.settings = settings;
        this.validFor = settings.getInt(Settings.KEYS.ANALYZER_CENTRAL_CACHE_VALID_DAYS, 90);

        String path = settings.getString(Settings.KEYS.CACHE_DIRECTORY);
        if (path == null) {
            LOGGER.debug("Cache directory is blank, using the data directory instead.");
            path = settings.getString(Settings.KEYS.DATA_DIRECTORY);
        }
        this.cache = new File(path, "cache");
        if (!cache.isDirectory() && !cache.mkdirs()) {
            throw new CacheException("Unable to create the cache directory");
        }
    }

    @Override
    public List<MavenArtifact> searchSha1(String sha1) {
        try {
            File dir = getDirectorty(sha1);
            boolean cacheIsValid = true;
            if (dir.isDirectory()) {
                List<MavenArtifact> list = new ArrayList<>();
                for (File f : dir.listFiles()) {
                    try (FileReader fr = new FileReader(f);
                            BufferedReader br = new BufferedReader(fr);) {
                        String date = br.readLine();
                        long epoch = Long.parseLong(date);
                        Instant createdOn = new Instant(epoch);
                        Interval cutoff = new Interval(createdOn, new Instant());
                        if (cutoff.toDuration().toPeriod().getDays() > validFor) {
                            cacheIsValid = false;
                            break;
                        }
                        String group = br.readLine();
                        String artifact = br.readLine();
                        String version = br.readLine();
                        String url = br.readLine();
                        String pom = br.readLine();
                        MavenArtifact ma = new MavenArtifact(group, artifact, version);
                        if (url != null && !url.isEmpty()) {
                            ma.setArtifactUrl(url);
                        }
                        if (pom != null && !pom.isEmpty()) {
                            ma.setPomUrl(pom);
                        }
                        list.add(ma);
                    } catch (FileNotFoundException ex) {
                        LOGGER.debug(String.format("Unable to read the cache file {}", f), ex);
                        cacheIsValid = false;
                        break;
                    } catch (IOException ex) {
                        LOGGER.debug(String.format("Unable to read the cache file {}", f), ex);
                        cacheIsValid = false;
                        break;
                    }
                }
                if (cacheIsValid) {
                    if (!list.isEmpty()) {
                        return list;
                    }
                } else {
                    for (File f : dir.listFiles()) {
                        FileUtils.deleteQuietly(f);
                    }
                }
            }
        } catch (CacheException ex) {
            LOGGER.debug("Unable to search the cache", ex);
        }
        return null;
    }

    @Override
    public void cacheData(String sha1, MavenArtifact ma) throws CacheException {
        File dir = getDirectorty(sha1);
        String name = String.format("%s.%s.%s.cache", ma.getGroupId(), ma.getArtifactId(), ma.getVersion());
        File file = new File(dir, name);
        if (file.isFile() && !file.delete()) {
            LOGGER.debug("Unable to delete the cached data");
            return;
        }
        try (FileWriter fw = new FileWriter(file);
                BufferedWriter bw = new BufferedWriter(fw);
                PrintWriter out = new PrintWriter(bw)) {

            Instant instant = new Instant();
            out.println(instant.getMillis());
            out.println(ma.getGroupId());
            out.println(ma.getArtifactId());
            out.println(ma.getVersion());
            out.println(ma.getArtifactUrl() == null ? "" : ma.getArtifactUrl());
            out.println(ma.getPomUrl() == null ? "" : ma.getPomUrl());
            out.flush();
            out.close();
        } catch (IOException ex) {
            throw new CacheException("Error writing cache entry", ex);
        }
    }

    @Override
    public void removeCacheEntries() {
        // do nothing - cache entries get invalidated as they are read in
    }

    private File getDirectorty(String sha1) throws CacheException {
        File dir = new File(cache, sha1.substring(0, 2)); //2
        dir = new File(dir, sha1.substring(2, 5)); //3
        dir = new File(dir, sha1.substring(5, 8)); //3
        dir = new File(dir, sha1.substring(8)); //33
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new CacheException(String.format("Unable to make cache directory: %s", dir));
        }
        return dir;
    }
}
