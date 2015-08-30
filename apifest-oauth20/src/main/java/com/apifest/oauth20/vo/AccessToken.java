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

package com.apifest.oauth20.vo;

import java.io.Serializable;
import java.util.Date;
import java.util.Map;

import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.annotation.JSONType;
import com.apifest.oauth20.JSONUtils;
import com.apifest.oauth20.RandomGenerator;


/**
 * Represents an access token.
 *
 * @author Rossitsa Borissova
 */
@JSONType(orders = { "access_token", "refresh_token", "token_type", "expires_in" })
//@JsonSerialize(include = Inclusion.NON_EMPTY)
public class AccessToken implements Serializable {

    private static final long serialVersionUID = 4322523635887085378L;

    @JSONField(name = "access_token")
    private String token = "";

    // not included when client_credentials
    @JSONField(name = "refresh_token")
    private String refreshToken = "";

    @JSONField(name = "expires_in")
    private String expiresIn = "";

    // bearer or mac
    @JSONField(name = "token_type")
    private String type = "";

    @JSONField(name = "scope")
    private String scope = "";

    @JSONField(deserialize=false, serialize=false)
    private boolean valid;

    @JSONField(deserialize=false, serialize=false)
    private String clientId = "";

    @JSONField(deserialize=false, serialize=false)
    private String codeId = "";

    @JSONField(deserialize=false, serialize=false)
    private String userId = "";

    @JSONField(deserialize=false, serialize=false)
    private Map<String, String> details = null;

    @JSONField(deserialize=false, serialize=false)
    private Long created;

    @JSONField(name = "refresh_expires_in")
    private String refreshExpiresIn = "";

    /**
     * Creates access token along with its refresh token.
     *
     * @param tokenType
     * @param expiresIn
     * @param scope
     */
    public AccessToken(String tokenType, String expiresIn, String scope, String refreshExpiresIn) {
        this(tokenType, expiresIn, scope, true, refreshExpiresIn);
    }

    /**
     * Creates access token. Used for generation of client_credentials type tokens with no refreshToken.
     *
     * @param tokenType
     * @param expiresIn
     * @param scope
     * @param createRefreshToken
     */
    public AccessToken(String tokenType, String expiresIn, String scope, boolean createRefreshToken, String refreshExpiresIn) {
        this.token = RandomGenerator.generateRandomString();
        if (createRefreshToken) {
            this.refreshToken = RandomGenerator.generateRandomString();
            this.refreshExpiresIn = (refreshExpiresIn != null && !refreshExpiresIn.isEmpty())? refreshExpiresIn : expiresIn;
        }
        this.expiresIn = expiresIn;
        this.type = tokenType;
        this.scope = scope;
        this.valid = true;
        this.created = (new Date()).getTime();
    }

    /**
     * Creates access token with already generated refresh token.
     *
     * @param tokenType
     * @param expiresIn
     * @param scope
     * @param createRefreshToken
     * @param refreshToken
     */
    public AccessToken(String tokenType, String expiresIn, String scope, String refreshToken, String refreshExpiresIn) {
        this.token = RandomGenerator.generateRandomString();
        this.expiresIn = expiresIn;
        this.type = tokenType;
        this.scope = scope;
        this.valid = true;
        this.created = (new Date()).getTime();
        this.refreshToken = refreshToken;
        this.refreshExpiresIn = (refreshExpiresIn != null && !refreshExpiresIn.isEmpty()) ? refreshExpiresIn : expiresIn;
    }

    public AccessToken() {
    }

    public String getToken() {
        return token;
    }

    public void setToken(String accessToken) {
        this.token = accessToken;
    }

    public String getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(String refreshToken) {
        this.refreshToken = refreshToken;
    }

    public String getExpiresIn() {
        return expiresIn;
    }

    public void setExpiresIn(String expiresIn) {
        this.expiresIn = expiresIn;
    }

    public String getType() {
        return type;
    }

    public void setType(String tokenType) {
        this.type = tokenType;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public boolean isValid() {
        return valid;
    }

    public void setValid(boolean valid) {
        this.valid = valid;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getCodeId() {
        return codeId;
    }

    public void setCodeId(String codeId) {
        this.codeId = codeId;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public Map<String, String> getDetails() {
        return details;
    }

    public void setDetails(Map<String, String> details) {
        this.details = details;
    }

    public Long getCreated() {
        return created;
    }

    public void setCreated(Long created) {
        this.created = created;
    }

    public String getRefreshExpiresIn() {
        return refreshExpiresIn;
    }

    public void setRefreshExpiresIn(String refreshExpiresIn) {
        this.refreshExpiresIn = refreshExpiresIn;
    }

    public static AccessToken loadFromMap(Map<String, Object> map) {
        AccessToken accessToken = new AccessToken();
        accessToken.token = (String) map.get("token");
        accessToken.refreshToken = (String) map.get("refreshToken");
        accessToken.expiresIn = (String) map.get("expiresIn");
        accessToken.type = (String) map.get("type");
        accessToken.scope = (String) map.get("scope");
        accessToken.valid = (Boolean) map.get("valid");
        accessToken.clientId = (String) map.get("clientId");
        accessToken.codeId = (String) map.get("codeId");
        accessToken.userId = (String) map.get("userId");
        accessToken.created = (Long) map.get("created");
        accessToken.details = JSONUtils.convertStringToMap((String) map.get("details"));
        accessToken.refreshExpiresIn = (String) ((map.get("refreshExpiresIn") != null ? map.get("refreshExpiresIn") : accessToken.expiresIn));
        return accessToken;
    }

    public static AccessToken loadFromStringMap(Map<String, String> map) {
        AccessToken accessToken = new AccessToken();
        accessToken.token = map.get("token");
        accessToken.refreshToken = map.get("refreshToken");
        accessToken.expiresIn = map.get("expiresIn");
        accessToken.type = map.get("type");
        accessToken.scope = map.get("scope");
        accessToken.valid = Boolean.parseBoolean(map.get("valid"));
        accessToken.clientId = map.get("clientId");
        accessToken.codeId = map.get("codeId");
        accessToken.userId = map.get("userId");
        accessToken.created = Long.parseLong(map.get("created"));
        accessToken.details = JSONUtils.convertStringToMap(map.get("details"));
        accessToken.refreshExpiresIn = map.get("refreshExpiresIn") != null ? map.get("refreshExpiresIn") : accessToken.expiresIn;
        return accessToken;
    }

    public boolean tokenExpired() {
        // expires_in is in seconds
        Long expiresInSec = Long.valueOf(getExpiresIn()) * 1000;
        Long currentTime = System.currentTimeMillis();
        if (expiresInSec + getCreated() < currentTime) {
            return true;
        }
        return false;
    }

    public boolean refreshTokenExpired() {
        Long refreshExpiresInSec = Long.valueOf(getRefreshExpiresIn()) * 1000;
        Long currentTime = System.currentTimeMillis();
        if (refreshExpiresInSec + getCreated() < currentTime) {
            return true;
        }
        return false;
    }

}