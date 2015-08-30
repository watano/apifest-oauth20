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

import java.net.MalformedURLException;
import java.net.URL;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.apifest.oauth20.OAuthException;
import com.apifest.oauth20.Response;

/**
 * Represents authorization code request.
 *
 * @author Rossitsa Borissova
 */
public class AuthRequest {

    private static final String CLIENT_ID = "client_id";
    private static final String RESPONSE_TYPE = "response_type";
    private static final String REDIRECT_URI = "redirect_uri";
    private static final String STATE = "state";
    private static final String SCOPE = "scope";
    private static final String USER_ID = "user_id";
    private static final String RESPONSE_TYPE_CODE = "code";

    private String clientId;
    private String responseType;
    private String redirectUri;
    private String state;
    private String scope;

    // additional field for identifying token-associated user
    private String userId;

    @SuppressWarnings("unchecked")
	public AuthRequest(HttpServletRequest request) {
        if (request.getParameterMap() != null) {
			Map<String, List<String>> params = request.getParameterMap();
            this.clientId = QueryParameter.getFirstElement(params, CLIENT_ID);
            this.responseType = QueryParameter.getFirstElement(params, RESPONSE_TYPE);
            this.redirectUri = QueryParameter.getFirstElement(params, REDIRECT_URI);
            this.state = QueryParameter.getFirstElement(params, STATE);
            this.scope = QueryParameter.getFirstElement(params, SCOPE);
            this.userId = QueryParameter.getFirstElement(params, USER_ID);
        }
    }

    public String getClientId() {
        return clientId;
    }

    public String getResponseType() {
        return responseType;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public String getState() {
        return state;
    }

    public String getScope() {
        return scope;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public void validate() throws OAuthException {
        if (!RESPONSE_TYPE_CODE.equals(responseType)) {
            throw new OAuthException(Response.RESPONSE_TYPE_NOT_SUPPORTED, HttpServletResponse.SC_BAD_REQUEST);
        }
        if (!isValidURI(redirectUri)) {
            throw new OAuthException(Response.INVALID_REDIRECT_URI, HttpServletResponse.SC_BAD_REQUEST);
        }
    }

    public static boolean isValidURI(String uri) {
        try {
            new URL(uri);
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }
}
