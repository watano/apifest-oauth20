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

import java.nio.charset.Charset;
import java.util.Date;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.alibaba.fastjson.JSON;
import com.apifest.oauth20.api.AuthenticationException;
import com.apifest.oauth20.api.ICustomGrantTypeHandler;
import com.apifest.oauth20.api.IUserAuthentication;
import com.apifest.oauth20.api.UserDetails;
import com.apifest.oauth20.persistence.DBManager;
import com.apifest.oauth20.util.ServletUtils;
import com.apifest.oauth20.vo.AccessToken;
import com.apifest.oauth20.vo.ApplicationInfo;
import com.apifest.oauth20.vo.AuthCode;
import com.apifest.oauth20.vo.AuthRequest;
import com.apifest.oauth20.vo.ClientCredentials;
import com.apifest.oauth20.vo.TokenRequest;

import jodd.util.Base64;

/**
 * Main class for authorization.
 *
 * @author Rossitsa Borissova
 */
@Service
public class AuthorizationServer {
    static final String BASIC = "Basic ";
    private static final String TOKEN_TYPE_BEARER = "Bearer";

    protected static Logger log = LoggerFactory.getLogger(AuthorizationServer.class);
    
	@Autowired
    protected DBManager db;
	@Autowired
    protected ScopeService scopeService;
	
    public String customGrantType;
	private String userAuthClass;
	private String customGrantTypeClass;

    public ClientCredentials issueClientCredentials(HttpServletRequest req) throws OAuthException {
        ClientCredentials creds = null;
        String content = ServletUtils.getContent(req);
        String contentType = req.getContentType();

        if (contentType != null && contentType.contains(Response.APPLICATION_JSON)) {            
            ApplicationInfo appInfo;
            try {
                appInfo = JSON.parseObject(content, ApplicationInfo.class);
                if (appInfo.valid()) {
                    String[] scopeList = appInfo.getScope().split(" ");
                    for (String s : scopeList) {
                        // TODO: add cache for scope
                        if (db.findScope(s) == null) {
                            throw new OAuthException(Response.SCOPE_NOT_EXIST, HttpServletResponse.SC_BAD_REQUEST);
                        }
                    }
                    // check client_id, client_secret passed
                    if ((appInfo.getId() != null && appInfo.getId().length() > 0) &&
                            (appInfo.getSecret() != null && appInfo.getSecret().length() > 0)) {
                        // if a client app with this client_id already registered
                        if (db.findClientCredentials(appInfo.getId()) == null) {
                            creds = new ClientCredentials(appInfo.getName(), appInfo.getScope(), appInfo.getDescription(),
                                appInfo.getRedirectUri(), appInfo.getId(), appInfo.getSecret(), appInfo.getApplicationDetails());
                        } else {
                            throw new OAuthException(Response.ALREADY_REGISTERED_APP, HttpServletResponse.SC_BAD_REQUEST);
                        }
                    } else {
                        creds = new ClientCredentials(appInfo.getName(), appInfo.getScope(), appInfo.getDescription(),
                                appInfo.getRedirectUri(), appInfo.getApplicationDetails());
                    }
                    db.storeClientCredentials(creds);
                } else {
                    throw new OAuthException(Response.NAME_OR_SCOPE_OR_URI_IS_NULL, HttpServletResponse.SC_BAD_REQUEST);
                }
            } catch (Exception e) {
                throw new OAuthException(e, Response.CANNOT_REGISTER_APP, HttpServletResponse.SC_BAD_REQUEST);
            }
        } else {
            throw new OAuthException(Response.UNSUPPORTED_MEDIA_TYPE, HttpServletResponse.SC_BAD_REQUEST);
        }
        return creds;
    }

    // /authorize?response_type=code&client_id=s6BhdRkqt3&state=xyz&redirect_uri=https%3A%2F%2Fclient%2Eexample%2Ecom%2Fcb
    public String issueAuthorizationCode(HttpServletRequest req) throws OAuthException {
        AuthRequest authRequest = new AuthRequest(req);
        log.debug("received client_id:" + authRequest.getClientId());
        if (!isActiveClientId(authRequest.getClientId())) {
            throw new OAuthException(Response.INVALID_CLIENT_ID, HttpServletResponse.SC_BAD_REQUEST);
        }
        authRequest.validate();

        String scope = scopeService.getValidScope(authRequest.getScope(), authRequest.getClientId());
        if (scope == null) {
            throw new OAuthException(Response.SCOPE_NOK_MESSAGE, HttpServletResponse.SC_BAD_REQUEST);
        }

        AuthCode authCode = new AuthCode(generateCode(), authRequest.getClientId(), authRequest.getRedirectUri(),
                authRequest.getState(), scope, authRequest.getResponseType(), authRequest.getUserId());
        log.debug("authCode: {}", authCode.getCode());
        db.storeAuthCode(authCode);

        // return redirect URI, append param code=[Authcode]
        String redirectUri = authRequest.getRedirectUri();
        if(redirectUri.indexOf("?")>0){
        	redirectUri += "code="+authCode.getCode();
        }else{
        	redirectUri += "?code="+authCode.getCode();        	
        }
        return redirectUri;
    }

    public AccessToken issueAccessToken(HttpServletRequest req) throws OAuthException {
        TokenRequest tokenRequest = new TokenRequest(req);
        tokenRequest.validate();
        // check valid client_id, client_secret and status of the client app should be active
        if (!isActiveClient(tokenRequest.getClientId(), tokenRequest.getClientSecret())) {
            throw new OAuthException(Response.INVALID_CLIENT_CREDENTIALS, HttpServletResponse.SC_BAD_REQUEST);
        }

        AccessToken accessToken = null;
        if (TokenRequest.AUTHORIZATION_CODE.equals(tokenRequest.getGrantType())) {
            AuthCode authCode = findAuthCode(tokenRequest);
            // TODO: REVISIT: Move client_id check to db query
            if (authCode != null) {
                if (!tokenRequest.getClientId().equals(authCode.getClientId())) {
                    throw new OAuthException(Response.INVALID_CLIENT_ID, HttpServletResponse.SC_BAD_REQUEST);
                }
                if (authCode.getRedirectUri() != null
                        && !tokenRequest.getRedirectUri().equals(authCode.getRedirectUri())) {
                    throw new OAuthException(Response.INVALID_REDIRECT_URI, HttpServletResponse.SC_BAD_REQUEST);
                } else {
                    // invalidate the auth code
                    db.updateAuthCodeValidStatus(authCode.getCode(), false);
                    accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD,authCode.getScope()),
                            authCode.getScope(), getExpiresIn(TokenRequest.REFRESH_TOKEN, authCode.getScope()));
                    accessToken.setUserId(authCode.getUserId());
                    accessToken.setClientId(authCode.getClientId());
                    accessToken.setCodeId(authCode.getId());
                    db.storeAccessToken(accessToken);
                }
            } else {
                throw new OAuthException(Response.INVALID_AUTH_CODE, HttpServletResponse.SC_BAD_REQUEST);
            }
        } else if (TokenRequest.REFRESH_TOKEN.equals(tokenRequest.getGrantType())) {
            accessToken = db.findAccessTokenByRefreshToken(tokenRequest.getRefreshToken(), tokenRequest.getClientId());
            if (accessToken != null) {
                if (!accessToken.refreshTokenExpired()) {
                    String validScope = null;
                    if (tokenRequest.getScope() != null) {
                        if (scopeService.scopeAllowed(tokenRequest.getScope(), accessToken.getScope())) {
                            validScope = tokenRequest.getScope();
                        } else {
                            throw new OAuthException(Response.SCOPE_NOK_MESSAGE, HttpServletResponse.SC_BAD_REQUEST);
                        }
                    } else {
                        validScope = accessToken.getScope();
                    }
                    db.updateAccessTokenValidStatus(accessToken.getToken(), false);
                    AccessToken newAccessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD,
                            validScope), validScope, accessToken.getRefreshToken(), accessToken.getRefreshExpiresIn());
                    newAccessToken.setUserId(accessToken.getUserId());
                    newAccessToken.setDetails(accessToken.getDetails());
                    newAccessToken.setClientId(accessToken.getClientId());
                    db.storeAccessToken(newAccessToken);
                    db.removeAccessToken(accessToken.getToken());
                    return newAccessToken;
                } else {
                    db.removeAccessToken(accessToken.getToken());
                    throw new OAuthException(Response.INVALID_REFRESH_TOKEN, HttpServletResponse.SC_BAD_REQUEST);
                }
            } else {
                throw new OAuthException(Response.INVALID_REFRESH_TOKEN, HttpServletResponse.SC_BAD_REQUEST);
            }
        } else if (TokenRequest.CLIENT_CREDENTIALS.equals(tokenRequest.getGrantType())) {
            ClientCredentials clientCredentials = db.findClientCredentials(tokenRequest.getClientId());
            String scope = scopeService.getValidScopeByScope(tokenRequest.getScope(), clientCredentials.getScope());
            if (scope == null) {
                throw new OAuthException(Response.SCOPE_NOK_MESSAGE, HttpServletResponse.SC_BAD_REQUEST);
            }

            accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.CLIENT_CREDENTIALS, scope),
                    scope, false, null);
            accessToken.setClientId(tokenRequest.getClientId());
            Map<String, String> applicationDetails = clientCredentials.getApplicationDetails();
            if ((applicationDetails != null) && (applicationDetails.size() > 0)) {
                accessToken.setDetails(applicationDetails);
            }
            db.storeAccessToken(accessToken);
        } else if (TokenRequest.PASSWORD.equals(tokenRequest.getGrantType())) {
            String scope = scopeService.getValidScope(tokenRequest.getScope(), tokenRequest.getClientId());
            if (scope == null) {
                throw new OAuthException(Response.SCOPE_NOK_MESSAGE, HttpServletResponse.SC_BAD_REQUEST);
            }

            try {
                UserDetails userDetails = authenticateUser(tokenRequest.getUsername(), tokenRequest.getPassword(), req);
                if (userDetails != null && userDetails.getUserId() != null) {
                    accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD, scope), scope,
                            getExpiresIn(TokenRequest.REFRESH_TOKEN, scope));
                    accessToken.setUserId(userDetails.getUserId());
                    accessToken.setDetails(userDetails.getDetails());
                    accessToken.setClientId(tokenRequest.getClientId());
                    db.storeAccessToken(accessToken);
                } else {
                    throw new OAuthException(Response.INVALID_USERNAME_PASSWORD, HttpServletResponse.SC_UNAUTHORIZED);
                }
            } catch (AuthenticationException e) {
                // in case some custom response should be returned other than HTTP 401
                // for instance, if the user authentication requires more user details as a subsequent step
                if (e.getResponse() != null) {
                	//FIXME
                    throw new OAuthException(e, e.getMessage(), 500);
                } else {
                    log.error("Cannot authenticate user", e);
                    throw new OAuthException(e, Response.CANNOT_AUTHENTICATE_USER, HttpServletResponse.SC_UNAUTHORIZED); // NOSONAR
                }
            }
        } else if (tokenRequest.getGrantType().equals(customGrantType)) {
            String scope = scopeService.getValidScope(tokenRequest.getScope(), tokenRequest.getClientId());
            if (scope == null) {
                throw new OAuthException(Response.SCOPE_NOK_MESSAGE, HttpServletResponse.SC_BAD_REQUEST);
            }
            try {
                accessToken = new AccessToken(TOKEN_TYPE_BEARER, getExpiresIn(TokenRequest.PASSWORD, scope), scope,
                        getExpiresIn(TokenRequest.REFRESH_TOKEN, scope));
                accessToken.setClientId(tokenRequest.getClientId());
                UserDetails userDetails = callCustomGrantTypeHandler(req);
                if (userDetails != null && userDetails.getUserId() != null) {
                    accessToken.setUserId(userDetails.getUserId());
                    accessToken.setDetails(userDetails.getDetails());
                }
                db.storeAccessToken(accessToken);
            } catch (AuthenticationException e) {
                log.error("Cannot authenticate user", e);
                throw new OAuthException(e, Response.CANNOT_AUTHENTICATE_USER, HttpServletResponse.SC_UNAUTHORIZED);
            }
        }
        return accessToken;
    }

    protected UserDetails authenticateUser(String username, String password, HttpServletRequest authRequest) throws AuthenticationException {
        UserDetails userDetails = null;
        IUserAuthentication ua;
        if (getUserAuthenticationClass() != null) {
            try {
                ua = getUserAuthenticationClass().newInstance();
                userDetails = ua.authenticate(username, password, authRequest);
            } catch (InstantiationException e) {
                log.error("cannot instantiate user authentication class", e);
                throw new AuthenticationException(e.getMessage());
            } catch (IllegalAccessException e) {
                log.error("cannot instantiate user authentication class", e);
                throw new AuthenticationException(e.getMessage());
            }
        } else {
            // if no specific UserAuthentication used, always returns customerId - 12345
            userDetails = new UserDetails("12345", null);
        }
        return userDetails;
    }

	protected UserDetails callCustomGrantTypeHandler(HttpServletRequest authRequest) throws AuthenticationException {
        UserDetails userDetails = null;
        ICustomGrantTypeHandler customHandler;
        if (getCustomGrantTypeHandler() != null) {
            try {
                customHandler = getCustomGrantTypeHandler().newInstance();
                userDetails = customHandler.execute(authRequest);
            } catch (InstantiationException e) {
                log.error("cannot instantiate custom grant_type class", e);
                throw new AuthenticationException(e.getMessage());
            } catch (IllegalAccessException e) {
                log.error("cannot instantiate custom grant_type class", e);
                throw new AuthenticationException(e.getMessage());
            }
        }
        return userDetails;
    }

	public static String [] getBasicAuthorizationClientCredentials(HttpServletRequest req) {
        // extract Basic Authorization header
        String authHeader = req.getHeader("Authorization");
        String [] clientCredentials = new String [2];
        if (authHeader != null && authHeader.contains(BASIC)) {
            String value = authHeader.replace(BASIC, "");
            byte[] decodedBytes = Base64.decode(value);
            String decoded = new String(decodedBytes, Charset.forName("UTF-8"));
            // client_id:client_secret - should be changed by client password
            String[] str = decoded.split(":");
            if (str.length == 2) {
                clientCredentials [0] = str[0];
                clientCredentials [1]  = str[1];
            }
        }
        return clientCredentials;
    }

    protected AuthCode findAuthCode(TokenRequest tokenRequest) {
        return db.findAuthCode(tokenRequest.getCode(), tokenRequest.getRedirectUri());
    }

    public AccessToken isValidToken(String token) {
        AccessToken accessToken = db.findAccessToken(token);
        if (accessToken != null && accessToken.isValid()) {
            if (accessToken.tokenExpired()) {
                db.updateAccessTokenValidStatus(accessToken.getToken(), false);
                return null;
            }
            return accessToken;
        }
        return null;
    }

    public ApplicationInfo getApplicationInfo(String clientId) {
        ApplicationInfo appInfo = null;
        ClientCredentials creds = db.findClientCredentials(clientId);
        if (creds != null) {
            appInfo = new ApplicationInfo();
            appInfo.setName(creds.getName());
            appInfo.setDescription(creds.getDescr());
            appInfo.setId(clientId);
            appInfo.setSecret(creds.getSecret());
            appInfo.setScope(creds.getScope());
            appInfo.setRedirectUri(creds.getUri());
            appInfo.setRegistered(new Date(creds.getCreated()));
            appInfo.setStatus(creds.getStatus());
            appInfo.setApplicationDetails(creds.getApplicationDetails());
        }
        return appInfo;
    }

    protected String generateCode() {
        return AuthCode.generate();
    }

    protected boolean isActiveClientId(String clientId) {
        ClientCredentials creds = db.findClientCredentials(clientId);
        if (creds != null && creds.getStatus() == ClientCredentials.ACTIVE_STATUS) {
            return true;
        }
        return false;
    }

    // check only that clientId and clientSecret are valid, NOT that the status is active
    protected boolean isValidClientCredentials(String clientId, String clientSecret) {
        ClientCredentials creds = db.findClientCredentials(clientId);
        if (creds != null && creds.getSecret().equals(clientSecret)) {
            return true;
        }
        return false;
    }

    protected boolean isActiveClient(String clientId, String clientSecret) {
        ClientCredentials creds = db.findClientCredentials(clientId);
        if (creds != null && creds.getSecret().equals(clientSecret) && creds.getStatus() == ClientCredentials.ACTIVE_STATUS) {
            return true;
        }
        return false;
    }

    protected boolean isExistingClient(String clientId) {
        ClientCredentials creds = db.findClientCredentials(clientId);
        if (creds != null) {
            return true;
        }
        return false;
    }

    protected String getExpiresIn(String tokenGrantType, String scope) {
        return String.valueOf(scopeService.getExpiresIn(tokenGrantType, scope));
    }

    public boolean revokeToken(HttpServletRequest req) throws OAuthException {
        RevokeTokenRequest revokeRequest = new RevokeTokenRequest(req);
        revokeRequest.checkMandatoryParams();
        String clientId = revokeRequest.getClientId();
        // check valid client_id, status does not matter as token of inactive client app could be revoked too
        if (!isExistingClient(clientId)) {
            throw new OAuthException(Response.INVALID_CLIENT_ID, HttpServletResponse.SC_BAD_REQUEST);
        }
        String token = revokeRequest.getAccessToken();
        AccessToken accessToken = db.findAccessToken(token);
        if (accessToken != null) {
            if (accessToken.tokenExpired()) {
                log.debug("access token {} is expired", token);
                return true;
            }
            if (clientId.equals(accessToken.getClientId())) {
                db.removeAccessToken(accessToken.getToken());
                log.debug("access token {} set status invalid", token);
                return true;
            } else {
                log.debug("access token {} is not obtained for that clientId {}", token, clientId);
                return false;
            }
        }
        log.debug("access token {} not found", token);
        return false;
    }

    public boolean updateClientApp(HttpServletRequest req, String clientId) throws OAuthException {
        String content = ServletUtils.getContent(req);
        String contentType = req.getContentType();
        if (contentType != null && contentType.contains(Response.APPLICATION_JSON)) {
//            String clientId = getBasicAuthorizationClientId(req);
//            if (clientId == null) {
//                throw new OAuthException(Response.INVALID_CLIENT_ID, HttpServletResponse.SC_BAD_REQUEST);
//            }
            if (!isExistingClient(clientId)) {
                throw new OAuthException(Response.INVALID_CLIENT_ID, HttpServletResponse.SC_BAD_REQUEST);
            }
            ApplicationInfo appInfo;
            try {
                appInfo = JSON.parseObject(content, ApplicationInfo.class);
                if (appInfo.validForUpdate()) {
                    if (appInfo.getScope() != null) {
                        String[] scopeList = appInfo.getScope().split(" ");
                        for (String s : scopeList) {
                            if (db.findScope(s) == null) {
                                throw new OAuthException(Response.SCOPE_NOT_EXIST, HttpServletResponse.SC_BAD_REQUEST);
                            }
                        }
                    }
                    db.updateClientApp(clientId, appInfo.getScope(), appInfo.getDescription(), appInfo.getStatus(),
                                       appInfo.getApplicationDetails());
                } else {
                    throw new OAuthException(Response.UPDATE_APP_MANDATORY_PARAM_MISSING, HttpServletResponse.SC_BAD_REQUEST);
                }
            } catch (Exception e) {
                throw new OAuthException(e, Response.CANNOT_UPDATE_APP, HttpServletResponse.SC_BAD_REQUEST);
            }
        } else {
            throw new OAuthException(Response.UNSUPPORTED_MEDIA_TYPE, HttpServletResponse.SC_BAD_REQUEST);
        }
        return true;
    }

    @SuppressWarnings("unchecked")
	private Class<IUserAuthentication> getUserAuthenticationClass() {
		try {
			return (Class<IUserAuthentication>) Class.forName(userAuthClass);
		} catch (Exception e) {
			return null;
		}
	}

    @SuppressWarnings("unchecked")
	private Class<ICustomGrantTypeHandler> getCustomGrantTypeHandler() {
		try {
			return (Class<ICustomGrantTypeHandler>) Class.forName(customGrantTypeClass);
		} catch (Exception e) {
			return null;
		}
	}

}
