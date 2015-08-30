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

package com.apifest.oauth20;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.HashMap;
import java.util.Map;

import org.junit.Test;

/**
 * @author Rossitsa Borissova
 */
public class JSONUtilTest {

    @Test
    public void when_json_string_convert_to_list() throws Exception {
        // GIVEN
        String json = "{\"key1\":\"value1\", \"key2\":\"value2\"}";

        // WHEN
        Map<String, String> map = JSONUtils.convertStringToMap(json);

        // THEN
        assertNotNull(map.get("key1"));
    }

    @Test
    public void when_list_convert_to_json() throws Exception {
        // GIVEN
        Map<String, String> details = new HashMap<String, String>();
        details.put("key1", "value1");
        details.put("key2", "value2");

        // WHEN
        String json = JSONUtils.convertMapToJSON(details);

        // THEN
        assertTrue(json.toString().contains("\"key1\":\"value1\""));
        assertTrue(json.toString().contains("\"key2\":\"value2\""));
    }
}
