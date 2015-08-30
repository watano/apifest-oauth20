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

import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.apifest.oauth20.api.ExceptionEventHandler;
import com.apifest.oauth20.api.LifecycleHandler;
import com.apifest.oauth20.vo.AccessToken;
import com.apifest.oauth20.vo.ApplicationInfo;
import com.apifest.oauth20.vo.ClientCredentials;
import com.apifest.oauth20.vo.QueryParameter;

/**
 * Handler for requests received on the server.
 *
 * @author Rossitsa Borissova
 */
@Controller
@RequestMapping(value = "/oauth20")
public class HttpRequestHandler {

	protected static final String AUTH_CODE_URI = "/oauth20/auth-codes";
	protected static final String ACCESS_TOKEN_URI = "/oauth20/tokens";
	protected static final String ACCESS_TOKEN_VALIDATE_URI = "/oauth20/tokens/validate";
	// protected static final String APPLICATION_URI = "/oauth20/applications";
	protected static final String ACCESS_TOKEN_REVOKE_URI = "/oauth20/tokens/revoke";
	protected static final String OAUTH_CLIENT_SCOPE_URI = "/oauth20/scopes";

	protected static final Pattern OAUTH_CLIENT_SCOPE_PATTERN = Pattern
			.compile("/oauth20/scopes/((\\p{Alnum}+-?_?)+$)");
	// protected static final Pattern APPLICATION_PATTERN =
	// Pattern.compile("/oauth20/applications/([a-f[0-9]]+)$");

	protected Logger log = LoggerFactory.getLogger(HttpRequestHandler.class);

	protected static Logger accessTokensLog = LoggerFactory.getLogger("accessTokens");

	@Autowired
	public AuthorizationServer auth = new AuthorizationServer();

	@RequestMapping(method = RequestMethod.GET, value = "/oauth20/applications/{clientId}")
	public String getClientApplication(HttpServletRequest req, HttpServletResponse response,
			@RequestParam("clientId") String clientId) {
		ApplicationInfo appInfo = auth.getApplicationInfo(clientId);
		if (appInfo != null) {
			try {
				String json = JSON.toJSONString(appInfo);
				log.debug(json);
				response = Response.createOkResponse(response, json);
			} catch (Exception e) {
				log.error("error get application info", e);
				invokeExceptionHandler(e, req);
			}
		} else {
			Response.createResponse(response, HttpServletResponse.SC_NOT_FOUND, Response.CLIENT_APP_NOT_EXIST);
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.GET, value = ACCESS_TOKEN_VALIDATE_URI)
	public String tokenValidate(HttpServletRequest req, HttpServletResponse response) {
		String tokenParam = req.getParameter(QueryParameter.TOKEN);
		if (tokenParam == null || tokenParam.isEmpty()) {
			response = Response.createBadRequestResponse(response);
		} else {
			AccessToken token = auth.isValidToken(tokenParam);
			if (token != null) {
				String json = JSON.toJSONString(token);
				log.debug(json);
				response = Response.createOkResponse(response, json);
			} else {
				response = Response.createUnauthorizedResponse(response);
			}
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.POST, value = ACCESS_TOKEN_URI)
	public String token(HttpServletRequest req, HttpServletResponse response) {
		String contentType = req.getContentType();
		if (contentType != null && contentType.contains("application/x-www-form-urlencoded")) {
			try {
				AccessToken accessToken = auth.issueAccessToken(req);
				if (accessToken != null) {
					String jsonString = JSON.toJSONString(accessToken);
					log.debug("access token:" + jsonString);
					response = Response.createOkResponse(response, jsonString);
					accessTokensLog.debug("token {}", jsonString);
				}
			} catch (OAuthException ex) {
				response = Response.createOAuthExceptionResponse(response, ex);
				invokeExceptionHandler(ex, req);
			} catch (Exception e1) {
				log.error("error handle token", e1);
				invokeExceptionHandler(e1, req);
			}
			if (response == null) {
				response = Response.createBadRequestResponse(response, Response.CANNOT_ISSUE_TOKEN);
			}
		} else {
			response = Response.createResponse(response, HttpServletResponse.SC_BAD_REQUEST,
					Response.UNSUPPORTED_MEDIA_TYPE);
		}
		return "";
	}

	protected void invokeRequestEventHandlers(HttpServletRequest request, HttpServletResponse response) {
		invokeHandlers(request, response, LifecycleEventHandlers.getRequestEventHandlers());
	}

	protected void invokeResponseEventHandlers(HttpServletRequest request, HttpServletResponse response) {
		invokeHandlers(request, response, LifecycleEventHandlers.getResponseEventHandlers());
	}

	protected void invokeExceptionHandler(Exception ex, HttpServletRequest request) {
		List<Class<ExceptionEventHandler>> handlers = LifecycleEventHandlers.getExceptionHandlers();
		for (int i = 0; i < handlers.size(); i++) {
			try {
				ExceptionEventHandler handler = handlers.get(i).newInstance();
				handler.handleException(ex, request);
			} catch (InstantiationException e) {
				log.error("cannot instantiate exception handler", e);
				invokeExceptionHandler(e, request);
			} catch (IllegalAccessException e) {
				log.error("cannot invoke exception handler", e);
				invokeExceptionHandler(ex, request);
			}
		}
	}

	protected void invokeHandlers(HttpServletRequest request, HttpServletResponse response,
			List<Class<LifecycleHandler>> handlers) {
		for (int i = 0; i < handlers.size(); i++) {
			try {
				LifecycleHandler handler = handlers.get(i).newInstance();
				handler.handle(request, response);
			} catch (InstantiationException e) {
				log.error("cannot instantiate handler", e);
				invokeExceptionHandler(e, request);
			} catch (IllegalAccessException e) {
				log.error("cannot invoke handler", e);
				invokeExceptionHandler(e, request);
			}
		}
	}

	@RequestMapping(method = RequestMethod.GET, value = AUTH_CODE_URI)
	public String authorize(HttpServletRequest req, HttpServletResponse response) {
		try {
			String redirectURI = auth.issueAuthorizationCode(req);
			// TODO: validation http protocol?
			log.debug("redirectURI: {}", redirectURI);

			// return auth_code
			JSONObject obj = new JSONObject();
			obj.put("redirect_uri", redirectURI);
			response = Response.createOkResponse(response, obj.toString());
			accessTokensLog.info("authCode {}", obj.toString());
		} catch (OAuthException ex) {
			response = Response.createOAuthExceptionResponse(response, ex);
			invokeExceptionHandler(ex, req);
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.POST, value = "/oauth20/applications/{clientId}")
	public String register(HttpServletRequest req, HttpServletResponse response) {

		try {
			ClientCredentials creds = auth.issueClientCredentials(req);
			String jsonString = JSON.toJSONString(creds);
			log.debug("credentials:" + jsonString);
			response = Response.createOkResponse(response, jsonString);
		} catch (OAuthException ex) {
			response = Response.createOAuthExceptionResponse(response, ex);
			invokeExceptionHandler(ex, req);
		} catch (Exception e1) {
			log.error("error handle register", e1);
			invokeExceptionHandler(e1, req);
		}
		if (response == null) {
			response = Response.createBadRequestResponse(response, Response.CANNOT_REGISTER_APP);
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.POST, value = ACCESS_TOKEN_REVOKE_URI)
	public String tokenRevoke(HttpServletRequest req, HttpServletResponse response) {
		boolean revoked = false;
		try {
			revoked = auth.revokeToken(req);
		} catch (OAuthException e) {
			log.error("cannot revoke token", e);
			invokeExceptionHandler(e, req);
			Response.createOAuthExceptionResponse(response, e);
		}
		String json = "{\"revoked\":\"" + revoked + "\"}";
		response = Response.createOkResponse(response, json);
		return "";
	}

	@RequestMapping(method = RequestMethod.POST, value = OAUTH_CLIENT_SCOPE_URI)
	public String registerScope(HttpServletRequest req, HttpServletResponse response) {
		ScopeService scopeService = getScopeService();

		try {
			String responseMsg = scopeService.registerScope(req);
			response = Response.createOkResponse(response, responseMsg);
		} catch (OAuthException e) {
			invokeExceptionHandler(e, req);
			response = Response.createResponse(response, e.getHttpStatus(), e.getMessage());
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.PUT, value = OAUTH_CLIENT_SCOPE_URI)
	public String updateScope(HttpServletRequest req, HttpServletResponse response) {

		Matcher m = OAUTH_CLIENT_SCOPE_PATTERN.matcher(req.getPathInfo());
		if (m.find()) {
			String scopeName = m.group(1);
			ScopeService scopeService = getScopeService();
			try {
				String responseMsg = scopeService.updateScope(req, scopeName);
				response = Response.createOkResponse(response, responseMsg);
			} catch (OAuthException e) {
				invokeExceptionHandler(e, req);
				response = Response.createResponse(response, e.getHttpStatus(), e.getMessage());
			}
		} else {
			response = Response.createNotFoundResponse(response);
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.GET, value = OAUTH_CLIENT_SCOPE_URI)
	public String getAllScopes(HttpServletRequest req, HttpServletResponse response) {
		ScopeService scopeService = getScopeService();

		try {
			String jsonString = scopeService.getScopes(req);
			response = Response.createOkResponse(response, jsonString);
		} catch (OAuthException e) {
			invokeExceptionHandler(e, req);
			response = Response.createResponse(response, e.getHttpStatus(), e.getMessage());
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.GET, value = OAUTH_CLIENT_SCOPE_URI)
	public String getScope(HttpServletRequest req, HttpServletResponse response) {

		Matcher m = OAUTH_CLIENT_SCOPE_PATTERN.matcher(req.getPathInfo());
		if (m.find()) {
			String scopeName = m.group(1);
			ScopeService scopeService = getScopeService();
			try {
				String responseMsg = scopeService.getScopeByName(scopeName);
				response = Response.createOkResponse(response, responseMsg);
			} catch (OAuthException e) {
				invokeExceptionHandler(e, req);
				response = Response.createResponse(response, e.getHttpStatus(), e.getMessage());
			}
		} else {
			response = Response.createNotFoundResponse(response);
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.DELETE, value = OAUTH_CLIENT_SCOPE_URI)
	public String deleteScope(HttpServletRequest req, HttpServletResponse response) {

		Matcher m = OAUTH_CLIENT_SCOPE_PATTERN.matcher(req.getPathInfo());
		if (m.find()) {
			String scopeName = m.group(1);
			ScopeService scopeService = getScopeService();
			try {
				String responseMsg = scopeService.deleteScope(scopeName);
				response = Response.createOkResponse(response, responseMsg);
			} catch (OAuthException e) {
				invokeExceptionHandler(e, req);
				response = Response.createResponse(response, e.getHttpStatus(), e.getMessage());
			}
		} else {
			response = Response.createNotFoundResponse(response);
		}
		return "";
	}

	protected ScopeService getScopeService() {
		return new ScopeService();
	}

	@RequestMapping(method = RequestMethod.PUT, value = "/oauth20/applications/{clientId}")
	public String updateClientApplication(HttpServletRequest req, HttpServletResponse response,
			@RequestParam("clientId") String clientId) {
		try {
			if (auth.updateClientApp(req, clientId)) {
				response = Response.createOkResponse(response, Response.CLIENT_APP_UPDATED);
			}
		} catch (OAuthException ex) {
			response = Response.createOAuthExceptionResponse(response, ex);
			invokeExceptionHandler(ex, req);
		}
		return "";
	}

	@RequestMapping(method = RequestMethod.GET, value = "/oauth20/applications/{clientId}")
	public String getAllClientApplications(HttpServletRequest req, HttpServletResponse response) {
		List<ApplicationInfo> apps = filterClientApps(req, auth.db.getAllApplications());
		try {
			String jsonString = JSON.toJSONString(apps);
			response = Response.createOkResponse(response, jsonString);
		} catch (Exception e) {
			log.error("cannot list client applications", e);
			invokeExceptionHandler(e, req);
			response = Response.createResponse(response, HttpServletResponse.SC_BAD_REQUEST,
					Response.CANNOT_LIST_CLIENT_APPS);
		}

		return "";
	}

	protected List<ApplicationInfo> filterClientApps(HttpServletRequest req, List<ApplicationInfo> apps) {
		List<ApplicationInfo> filteredApps = new ArrayList<ApplicationInfo>();
		String status = req.getParameter("status");
		Integer statusInt = null;
		if (status != null && !status.isEmpty()) {
			try {
				statusInt = Integer.valueOf(status);
				for (ApplicationInfo app : apps) {
					if (app.getStatus() == statusInt) {
						filteredApps.add(app);
					}
				}
			} catch (NumberFormatException e) {
				// status is invalid, ignore it
				filteredApps = Collections.unmodifiableList(apps);
			}
		} else {
			filteredApps = Collections.unmodifiableList(apps);
		}
		return filteredApps;
	}

	@RequestMapping(method = RequestMethod.GET, value = ACCESS_TOKEN_URI)
	public String getAccessTokens(HttpServletRequest req, HttpServletResponse response) {
		String clientId = req.getParameter(QueryParameter.CLIENT_ID);
		String userId = req.getParameter(QueryParameter.USER_ID);
		if (clientId == null || clientId.isEmpty()) {
			response = Response.createBadRequestResponse(response,
					String.format(Response.MANDATORY_PARAM_MISSING, QueryParameter.CLIENT_ID));
		} else if (userId == null || userId.isEmpty()) {
			response = Response.createBadRequestResponse(response,
					String.format(Response.MANDATORY_PARAM_MISSING, QueryParameter.USER_ID));
		} else {
			// check that clientId exists, no matter whether it is active or not
			if (!auth.isExistingClient(clientId)) {
				response = Response.createBadRequestResponse(response, Response.INVALID_CLIENT_ID);
			} else {
				List<AccessToken> accessTokens = auth.db.getAccessTokenByUserIdAndClientApp(userId, clientId);
				String jsonString = JSON.toJSONString(accessTokens);
				response = Response.createOkResponse(response, jsonString);
			}
		}
		return "";
	}
}
