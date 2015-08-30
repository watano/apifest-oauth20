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

import java.io.IOException;
import java.util.Map;

import com.fasterxml.jackson.core.JsonGenerationException;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JavaType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Utility class for JSON transformations.
 *
 * @author Rossitsa Borissova
 */
public final class JSONUtils {

    private static Logger log = LoggerFactory.getLogger(JSONUtils.class);

    public static String convertMapToJSON(Map<String, String> list) {
        String result = null;
        try {
            ObjectMapper mapper = new ObjectMapper();
            result = mapper.writeValueAsString(list);
        } catch (JsonGenerationException e) {
            log.error("Cannot convert list to JSON format", e);
        } catch (JsonMappingException e) {
            log.error("Cannot convert list to JSON format", e);
        } catch (IOException e) {
            log.error("Cannot convert list to JSON format", e);
        }
        return result;
    }

    public static Map<String, String> convertStringToMap(String json) {
        ObjectMapper mapper = new ObjectMapper();
        Map<String, String> details = null;
        try {
            if (json != null) {
                JavaType listType = mapper.getTypeFactory().constructMapLikeType(Map.class, String.class, String.class);
                details = mapper.readValue(json, listType);
            }
        } catch (JsonParseException e) {
            log.error("Cannot convert json to map", e);
        } catch (JsonMappingException e) {
            log.error("Cannot convert json to map", e);
        } catch (IOException e) {
            log.error("Cannot convert json to map", e);
        }
        return details;
    }

}
