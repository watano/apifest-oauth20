/*
 * Copyright 2013-2014, ApiFest project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @author Apostol Terziev
 */
package com.apifest.oauth20.persistence;

import com.apifest.oauth20.OAuthServer;
import com.apifest.oauth20.persistence.hazelcast.HazelcastDBManager;

public class DBManagerFactory {

	public static volatile DBManager dbManager;

    public static final String REDIS_DB = "redis";
    public static final String MONGO_DB = "mongodb";
    public static final String DEFAULT_DB = "hazelcast";


    public synchronized static DBManager getInstance() {
        if (dbManager == null) {
            if (REDIS_DB.equalsIgnoreCase(OAuthServer.getDatabase())) {
                dbManager = new RedisDBManager();
                ((RedisDBManager) dbManager).setupDBManager();
            } else if (MONGO_DB.equalsIgnoreCase(OAuthServer.getDatabase())) {
                dbManager = new MongoDBManager();
            } else {
                dbManager = new HazelcastDBManager();
            }
        }
        return dbManager;
    }

    public static void init() {
        // that will instantiate a connection to the storage
        getInstance();
    }
}
