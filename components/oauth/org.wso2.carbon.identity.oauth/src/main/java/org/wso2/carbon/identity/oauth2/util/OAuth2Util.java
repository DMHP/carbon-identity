/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.apache.commons.io.Charsets;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.User;
import org.wso2.carbon.core.util.CryptoException;
import org.wso2.carbon.core.util.CryptoUtil;
import org.wso2.carbon.identity.core.util.IdentityDatabaseUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth.IdentityOAuthAdminException;
import org.wso2.carbon.identity.oauth.cache.AppInfoCache;
import org.wso2.carbon.identity.oauth.cache.CacheEntry;
import org.wso2.carbon.identity.oauth.cache.OAuthCache;
import org.wso2.carbon.identity.oauth.cache.OAuthCacheKey;
import org.wso2.carbon.identity.oauth.common.OAuthConstants;
import org.wso2.carbon.identity.oauth.common.exception.InvalidOAuthClientException;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDAO;
import org.wso2.carbon.identity.oauth.tokenprocessor.EncryptionDecryptionPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.HashingPersistenceProcessor;
import org.wso2.carbon.identity.oauth.tokenprocessor.TokenPersistenceProcessor;
import org.wso2.carbon.identity.oauth.dao.OAuthAppDO;
import org.wso2.carbon.identity.oauth.dao.OAuthConsumerDAO;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.dao.SQLQueries;
import org.wso2.carbon.identity.oauth2.model.AccessTokenDO;
import org.wso2.carbon.identity.oauth2.model.ClientCredentialDO;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;

/**
 * Utility methods for OAuth 2.0 implementation
 */
public class OAuth2Util {

    public static final String REMOTE_ACCESS_TOKEN = "REMOTE_ACCESS_TOKEN";
    public static final String JWT_ACCESS_TOKEN = "JWT_ACCESS_TOKEN";
    

    /*
     * OPTIONAL. A JSON string containing a space-separated list of scopes associated with this token, in the format
     * described in Section 3.3 of OAuth 2.0
     */
    public static final String SCOPE = "scope";

    /*
     * OPTIONAL. Client identifier for the OAuth 2.0 client that requested this token.
     */
    public static final String CLIENT_ID = "client_id";

    /*
     * OPTIONAL. Human-readable identifier for the resource owner who authorized this token.
     */
    public static final String USERNAME = "username";

    /*
     * OPTIONAL. Type of the token as defined in Section 5.1 of OAuth 2.0
     */
    public static final String TOKEN_TYPE = "token_type";

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token is not to be used before, as defined in JWT
     */
    public static final String NBF = "nbf";

    /*
     * OPTIONAL. Service-specific string identifier or list of string identifiers representing the intended audience for
     * this token, as defined in JWT
     */
    public static final String AUD = "aud";

    /*
     * OPTIONAL. String representing the issuer of this token, as defined in JWT
     */
    public static final String ISS = "iss";

    /*
     * OPTIONAL. String identifier for the token, as defined in JWT
     */
    public static final String JTI = "jti";

    /*
     * OPTIONAL. Subject of the token, as defined in JWT [RFC7519]. Usually a machine-readable identifier of the
     * resource owner who authorized this token.
     */
    public static final String SUB = "sub";

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token will expire, as defined in JWT
     */
    public static final String EXP = "exp";

    /*
     * OPTIONAL. Integer time-stamp, measured in the number of seconds since January 1 1970 UTC, indicating when this
     * token was originally issued, as defined in JWT
     */
    public static final String IAT = "iat";

    
    private static Log log = LogFactory.getLog(OAuth2Util.class);
    private static boolean cacheEnabled = OAuthServerConfiguration.getInstance().isCacheEnabled();
    private static OAuthCache cache = OAuthCache.getInstance();
    private static long timestampSkew = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
    private static ThreadLocal<Integer> clientTenatId = new ThreadLocal<>();
    private static ThreadLocal<OAuthTokenReqMessageContext> tokenRequestContext = new ThreadLocal<OAuthTokenReqMessageContext>();
    private static ThreadLocal<OAuthAuthzReqMessageContext> authzRequestContext = new ThreadLocal<OAuthAuthzReqMessageContext>();

    //system property used when RSA+OAEP dynamic encryption algorithm is enabled
    private static final String CIPHER_TRANSFORMATION_SYSTEM_PROPERTY = "org.wso2.CipherTransformation";
    //New columns introduced to store hash values when RSA + OAEP encryption is enabled.
    private static final String ACCESS_TOKEN_HASH = "ACCESS_TOKEN_HASH";
    private static final String REFRESH_TOKEN_HASH = "REFRESH_TOKEN_HASH";
    private static final String AUTHORIZATION_CODE_HASH = "AUTHORIZATION_CODE_HASH";
    private static final String CONSUMER_SECRET_HASH = "CONSUMER_SECRET_HASH";

    private OAuth2Util(){

    }
    
    /**
     * 
     * @return
     */
    public static OAuthAuthzReqMessageContext getAuthzRequestContext() {
	if (log.isDebugEnabled()) {
	    log.debug("Retreived OAuthAuthzReqMessageContext from threadlocal");
	}
	return authzRequestContext.get();
    }

    /**
     * 
     * @param context
     */
    public static void setAuthzRequestContext(OAuthAuthzReqMessageContext context) {
	authzRequestContext.set(context);
	if (log.isDebugEnabled()) {
	    log.debug("Added OAuthAuthzReqMessageContext to threadlocal");
	}
    }

    /**
     * 
     */
    public static void clearAuthzRequestContext() {
	authzRequestContext.remove();
	if (log.isDebugEnabled()) {
	    log.debug("Cleared OAuthAuthzReqMessageContext");
	}
    }
    
    /**
     * 
     * @return
     */
    public static OAuthTokenReqMessageContext getTokenRequestContext() {
	if (log.isDebugEnabled()) {
	    log.debug("Retreived OAuthTokenReqMessageContext from threadlocal");
	}
	return tokenRequestContext.get();
    }

    /**
     * 
     * @param context
     */
    public static void setTokenRequestContext(OAuthTokenReqMessageContext context) {
	tokenRequestContext.set(context);
	if (log.isDebugEnabled()) {
	    log.debug("Added OAuthTokenReqMessageContext to threadlocal");
	}
    }

    /**
     * 
     */
    public static void clearTokenRequestContext() {
	tokenRequestContext.remove();
	if (log.isDebugEnabled()) {
	    log.debug("Cleared OAuthTokenReqMessageContext");
	}
    }

    /**
     * @return
     */
    public static int getClientTenatId() {
        if (clientTenatId.get() == null) {
            return -1;
        }
        return clientTenatId.get().intValue();
    }

    /**
     * @param tenantId
     */
    public static void setClientTenatId(int tenantId) {
        Integer id = new Integer(tenantId);
        clientTenatId.set(id);
    }

    /**
     *
     */
    public static void clearClientTenantId() {
        clientTenatId.remove();
    }

    /**
     * Build a comma separated list of scopes passed as a String set by OLTU.
     *
     * @param scopes set of scopes
     * @return Comma separated list of scopes
     */
    public static String buildScopeString(String[] scopes) {
        if (scopes != null) {
            StringBuilder scopeString = new StringBuilder("");
            Arrays.sort(scopes);
            for (int i = 0; i < scopes.length; i++) {
                scopeString.append(scopes[i].trim());
                if (i != scopes.length - 1) {
                    scopeString.append(" ");
                }
            }
            return scopeString.toString();
        }
        return null;
    }

    /**
     * @param scopeStr
     * @return
     */
    public static String[] buildScopeArray(String scopeStr) {
        if (StringUtils.isNotBlank(scopeStr)) {
            scopeStr = scopeStr.trim();
            return scopeStr.split("\\s");
        }
        return new String[0];
    }

    /**
     * Authenticate the OAuth Consumer
     *
     * @param clientId             Consumer Key/Id
     * @param clientSecretProvided Consumer Secret issued during the time of registration
     * @return true, if the authentication is successful, false otherwise.
     * @throws IdentityOAuthAdminException Error when looking up the credentials from the database
     */
    public static boolean authenticateClient(String clientId, String clientSecretProvided)
            throws IdentityOAuthAdminException, IdentityOAuth2Exception, InvalidOAuthClientException {

        boolean cacheHit = false;
        String clientSecret = null;

        // Check the cache first.
        if (cacheEnabled) {
            CacheEntry cacheResult = cache.getValueFromCache(new OAuthCacheKey(clientId));
            if (cacheResult != null && cacheResult instanceof ClientCredentialDO) {
                ClientCredentialDO clientCredentialDO = (ClientCredentialDO) cacheResult;
                clientSecret = clientCredentialDO.getClientSecret();
                cacheHit = true;
                if (log.isDebugEnabled()) {
                    log.debug("Client credentials were available in the cache for client id : " +
                            clientId);
                }
            }
        }

        // Cache miss
        if (clientSecret == null) {
            OAuthConsumerDAO oAuthConsumerDAO = new OAuthConsumerDAO();
            clientSecret = oAuthConsumerDAO.getOAuthConsumerSecret(clientId);
            if (log.isDebugEnabled()) {
                log.debug("Client credentials were fetched from the database.");
            }
        }

        if (clientSecret == null) {
            if (log.isDebugEnabled()) {
                log.debug("Provided Client ID : " + clientId + "is not valid.");
            }
            return false;
        }

        if (!clientSecret.equals(clientSecretProvided)) {

            if (log.isDebugEnabled()) {
                log.debug("Provided the Client ID : " + clientId +
                        " and Client Secret do not match with the issued credentials.");
            }

            return false;
        }

        if (log.isDebugEnabled()) {
            log.debug("Successfully authenticated the client with client id : " + clientId);
        }

        if (cacheEnabled && !cacheHit) {

            cache.addToCache(new OAuthCacheKey(clientId), new ClientCredentialDO(clientSecret));
            if (log.isDebugEnabled()) {
                log.debug("Client credentials were added to the cache for client id : " + clientId);
            }
        }

        return true;
    }

    /**
     * Authenticate the OAuth consumer and return the username of user which own the provided client id and client
     * secret.
     *
     * @param clientId             Consumer Key/Id
     * @param clientSecretProvided Consumer Secret issued during the time of registration
     * @return Username of the user which own client id and client secret if authentication is
     * successful. Empty string otherwise.
     * @throws IdentityOAuthAdminException Error when looking up the credentials from the database
     */
    public static String getAuthenticatedUsername(String clientId, String clientSecretProvided)
            throws IdentityOAuthAdminException, IdentityOAuth2Exception, InvalidOAuthClientException {

        boolean cacheHit = false;
        String username = null;
        boolean isUsernameCaseSensitive = IdentityUtil.isUserStoreInUsernameCaseSensitive(username);

        if (OAuth2Util.authenticateClient(clientId, clientSecretProvided)) {
            // check cache
            if (cacheEnabled) {
                CacheEntry cacheResult = cache.getValueFromCache(new OAuthCacheKey(clientId + ":" + username));
                if (cacheResult != null && cacheResult instanceof ClientCredentialDO) {
                    // Ugh. This is fugly. Have to have a generic way of caching a key:value pair
                    username = ((ClientCredentialDO) cacheResult).getClientSecret();
                    cacheHit = true;
                    if (log.isDebugEnabled()) {
                        log.debug("Username was available in the cache : " +
                                username);
                    }
                }
            }

            if (username == null) {
                // Cache miss
                OAuthConsumerDAO oAuthConsumerDAO = new OAuthConsumerDAO();
                username = oAuthConsumerDAO.getAuthenticatedUsername(clientId, clientSecretProvided);
                if (log.isDebugEnabled()) {
                    log.debug("Username fetch from the database");
                }
            }

            if (username != null && cacheEnabled && !cacheHit) {
                /**
                 * Using the same ClientCredentialDO to host username. Semantically wrong since ClientCredentialDo
                 * accept a client secret and we're storing a username in the secret variable. Do we have to make our
                 * own cache key and cache entry class every time we need to put something to it? Ideal solution is
                 * to have a generalized way of caching a key:value pair
                 */
                if (isUsernameCaseSensitive){
                    cache.addToCache(new OAuthCacheKey(clientId + ":" + username), new ClientCredentialDO(username));
                }else {
                    cache.addToCache(new OAuthCacheKey(clientId + ":" + username.toLowerCase()), new ClientCredentialDO(username));
                }
                if (log.isDebugEnabled()){
                    log.debug("Caching username : " + username);
                }

            }
        }
        return username;
    }

    /**
     * Build the cache key string when storing Authz Code info in cache
     *
     * @param clientId  Client Id representing the client
     * @param authzCode Authorization Code issued to the client
     * @return concatenated <code>String</code> of clientId:authzCode
     */
    public static String buildCacheKeyStringForAuthzCode(String clientId, String authzCode) {
        return clientId + ":" + authzCode;
    }

    public static AccessTokenDO validateAccessTokenDO(AccessTokenDO accessTokenDO) {

        long validityPeriodMillis = accessTokenDO.getValidityPeriodInMillis();
        long issuedTime = accessTokenDO.getIssuedTime().getTime();
        long currentTime = System.currentTimeMillis();

        //check the validity of cached OAuth2AccessToken Response
        long skew = OAuthServerConfiguration.getInstance().getTimeStampSkewInSeconds() * 1000;
        if (issuedTime + validityPeriodMillis - (currentTime + skew) > 1000) {
            long refreshValidity = OAuthServerConfiguration.getInstance()
                    .getRefreshTokenValidityPeriodInSeconds() * 1000;
            if (issuedTime + refreshValidity - currentTime + skew > 1000) {
                //Set new validity period to response object
                accessTokenDO.setValidityPeriod((issuedTime + validityPeriodMillis - (currentTime + skew)) / 1000);
                accessTokenDO.setValidityPeriodInMillis(issuedTime + validityPeriodMillis - (currentTime + skew));
                //Set issued time period to response object
                accessTokenDO.setIssuedTime(new Timestamp(currentTime));
                return accessTokenDO;
            }
        }
        //returns null if cached OAuth2AccessToken response object is expired
        return null;
    }

    public static boolean checkAccessTokenPartitioningEnabled() {
        return OAuthServerConfiguration.getInstance().isAccessTokenPartitioningEnabled();
    }

    public static boolean checkUserNameAssertionEnabled() {
        return OAuthServerConfiguration.getInstance().isUserNameAssertionEnabled();
    }

    public static String getAccessTokenPartitioningDomains() {
        return OAuthServerConfiguration.getInstance().getAccessTokenPartitioningDomains();
    }

    public static Map<String, String> getAvailableUserStoreDomainMappings() throws
            IdentityOAuth2Exception {
        //TreeMap is used to ignore the case sensitivity of key. Because when user logged in, the case of the user name is ignored.
        Map<String, String> userStoreDomainMap = new TreeMap<String, String>(String.CASE_INSENSITIVE_ORDER);
        String domainsStr = getAccessTokenPartitioningDomains();
        if (domainsStr != null) {
            String[] userStoreDomainsArr = domainsStr.split(",");
            for (String userStoreDomains : userStoreDomainsArr) {
                String[] mapping = userStoreDomains.trim().split(":"); //A:foo.com , B:bar.com
                if (mapping.length < 2) {
                    throw new IdentityOAuth2Exception("Domain mapping has not defined correctly");
                }
                userStoreDomainMap.put(mapping[1].trim(), mapping[0].trim()); //key=domain & value=mapping
            }
        }
        return userStoreDomainMap;
    }

    public static String getUserStoreDomainFromUserId(String userId)
            throws IdentityOAuth2Exception {
        String userStore = null;
        if (userId != null) {
            String[] strArr = userId.split("/");
            if (strArr != null && strArr.length > 1) {
                userStore = strArr[0];
                Map<String, String> availableDomainMappings = getAvailableUserStoreDomainMappings();
                if (availableDomainMappings != null &&
                        availableDomainMappings.containsKey(userStore)) {
                    userStore = getAvailableUserStoreDomainMappings().get(userStore);
                }
            }
        }
        return userStore;
    }

    public static String getUserStoreDomainFromAccessToken(String apiKey)
            throws IdentityOAuth2Exception {
        String userStoreDomain = null;
        String userId;
        String decodedKey = new String(Base64.decodeBase64(apiKey.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
        String[] tmpArr = decodedKey.split(":");
        if (tmpArr != null) {
            userId = tmpArr[1];
            if (userId != null) {
                userStoreDomain = getUserStoreDomainFromUserId(userId);
            }
        }
        return userStoreDomain;
    }

    public static String getAccessTokenStoreTableFromUserId(String userId)
            throws IdentityOAuth2Exception {
        String accessTokenStoreTable = OAuthConstants.ACCESS_TOKEN_STORE_TABLE;
        String userStore;
        if (userId != null) {
            String[] strArr = userId.split("/");
            if (strArr != null && strArr.length > 1) {
                userStore = strArr[0];
                Map<String, String> availableDomainMappings = getAvailableUserStoreDomainMappings();
                if (availableDomainMappings != null &&
                        availableDomainMappings.containsKey(userStore)) {
                    accessTokenStoreTable = accessTokenStoreTable + "_" +
                            availableDomainMappings.get(userStore);
                }
            }
        }
        return accessTokenStoreTable;
    }

    public static String getAccessTokenStoreTableFromAccessToken(String apiKey)
            throws IdentityOAuth2Exception {
        String userId = getUserIdFromAccessToken(apiKey); //i.e: 'foo.com/admin' or 'admin'
        return getAccessTokenStoreTableFromUserId(userId);
    }

    public static String getUserIdFromAccessToken(String apiKey) {
        String userId = null;
        String decodedKey = new String(Base64.decodeBase64(apiKey.getBytes(Charsets.UTF_8)), Charsets.UTF_8);
        String[] tmpArr = decodedKey.split(":");
        if (tmpArr != null) {
            userId = tmpArr[1];
        }
        return userId;
    }

    public static long getTokenExpireTimeMillis(AccessTokenDO accessTokenDO) {

        if (accessTokenDO == null) {
            throw new IllegalArgumentException("accessTokenDO is " + "\'NULL\'");
        }

        long currentTime;
        long validityPeriodMillis = accessTokenDO.getValidityPeriodInMillis();

        if(validityPeriodMillis < 0){
            log.debug("Access Token : " + accessTokenDO.getAccessToken() + " has infinite lifetime");
            return -1;
        }

        long refreshTokenValidityPeriodMillis = accessTokenDO.getRefreshTokenValidityPeriodInMillis();
        long issuedTime = accessTokenDO.getIssuedTime().getTime();
        currentTime = System.currentTimeMillis();
        long refreshTokenIssuedTime = accessTokenDO.getRefreshTokenIssuedTime().getTime();
        long accessTokenValidity = issuedTime + validityPeriodMillis - (currentTime + timestampSkew);
        long refreshTokenValidity = (refreshTokenIssuedTime + refreshTokenValidityPeriodMillis)
                                    - (currentTime + timestampSkew);
        if(accessTokenValidity > 1000 && refreshTokenValidity > 1000){
            return accessTokenValidity;
        }
        return 0;
    }

    public static long getRefreshTokenExpireTimeMillis(AccessTokenDO accessTokenDO) {

        if (accessTokenDO == null) {
            throw new IllegalArgumentException("accessTokenDO is " + "\'NULL\'");
        }

        long currentTime;
        long refreshTokenValidityPeriodMillis = accessTokenDO.getRefreshTokenValidityPeriodInMillis();

        if (refreshTokenValidityPeriodMillis < 0) {
            log.debug("Refresh Token has infinite lifetime");
            return -1;
        }

        currentTime = System.currentTimeMillis();
        long refreshTokenIssuedTime = accessTokenDO.getRefreshTokenIssuedTime().getTime();
        long refreshTokenValidity = (refreshTokenIssuedTime + refreshTokenValidityPeriodMillis)
                                    - (currentTime + timestampSkew);
        if(refreshTokenValidity > 1000){
            return refreshTokenValidity;
        }
        return 0;
    }

    public static long getAccessTokenExpireMillis(AccessTokenDO accessTokenDO) {

        if(accessTokenDO == null){
            throw new IllegalArgumentException("accessTokenDO is " + "\'NULL\'");
        }
        long currentTime;
        long validityPeriodMillis = accessTokenDO.getValidityPeriodInMillis();

        if (validityPeriodMillis < 0) {
            log.debug("Access Token has infinite lifetime");
            return -1;
        }

        long issuedTime = accessTokenDO.getIssuedTime().getTime();
        currentTime = System.currentTimeMillis();
        long validityMillis = issuedTime + validityPeriodMillis - (currentTime + timestampSkew);
        if (validityMillis > 1000) {
            return validityMillis;
        } else {
            return 0;
        }
    }

    public static int getTenantId(String tenantDomain) throws IdentityOAuth2Exception {
        RealmService realmService = OAuthComponentServiceHolder.getRealmService();
        try {
            return realmService.getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            String error = "Error in obtaining tenant ID from tenant domain : " + tenantDomain;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    public static String getTenantDomain(int tenantId) throws IdentityOAuth2Exception {
        RealmService realmService = OAuthComponentServiceHolder.getRealmService();
        try {
            return realmService.getTenantManager().getDomain(tenantId);
        } catch (UserStoreException e) {
            String error = "Error in obtaining tenant domain from tenant ID : " + tenantId;
            throw new IdentityOAuth2Exception(error, e);
        }
    }

    public static int getTenantIdFromUserName(String username) throws IdentityOAuth2Exception {

        String domainName = MultitenantUtils.getTenantDomain(username);
        return getTenantId(domainName);
    }

    public static String hashScopes(String[] scope){
        return DigestUtils.md5Hex(OAuth2Util.buildScopeString(scope));
    }

    public static String hashScopes(String scope){
        if (scope != null) {
            //first converted to an array to sort the scopes
            return DigestUtils.md5Hex(OAuth2Util.buildScopeString(buildScopeArray(scope)));
        } else {
           return null;
        }
    }

    public static AuthenticatedUser getUserFromUserName(String username) throws IllegalArgumentException{
        if (StringUtils.isNotBlank(username)) {
            String tenantDomain = MultitenantUtils.getTenantDomain(username);
            String tenantAwareUsername = MultitenantUtils.getTenantAwareUsername(username);
            String tenantAwareUsernameWithNoUserDomain = UserCoreUtil.removeDomainFromName(tenantAwareUsername);
            String userStoreDomain = IdentityUtil.extractDomainFromName(username).toUpperCase();
            AuthenticatedUser user = new AuthenticatedUser();
            user.setUserName(tenantAwareUsernameWithNoUserDomain);
            user.setTenantDomain(tenantDomain);
            user.setUserStoreDomain(userStoreDomain);

            return user;
        }
        throw  new IllegalArgumentException("Cannot create user from empty user name");
    }

    public static String getIDTokenIssuer() {
        String issuer = OAuthServerConfiguration.getInstance().getOpenIDConnectIDTokenIssuerIdentifier();
        if (StringUtils.isBlank(issuer)) {
            issuer = OAuthURL.getOAuth2TokenEPUrl();
        }
        return issuer;
    }

    /**
     * Checks whether the response type is implicit.
     * @param responseType
     * @return
     */
    public static boolean isImplicitResponseType(String responseType) {
        if(StringUtils.isNotBlank(responseType) && (responseType.contains(ResponseType.TOKEN.toString()) ||
                responseType.contains(OAuthConstants.ID_TOKEN))) {
            return true;
        }
        return false;
    }

    /**
     * Get Oauth application information
     *
     * @param clientId
     * @return Oauth app information
     * @throws IdentityOAuth2Exception
     * @throws InvalidOAuthClientException
     */
    public static OAuthAppDO getAppInformationByClientId(String clientId)
            throws IdentityOAuth2Exception, InvalidOAuthClientException {

        OAuthAppDO oAuthAppDO = AppInfoCache.getInstance().getValueFromCache(clientId);
        if (oAuthAppDO != null) {
            return oAuthAppDO;
        } else {
            oAuthAppDO = new OAuthAppDAO().getAppInformation(clientId);
            AppInfoCache.getInstance().addToCache(clientId, oAuthAppDO);
            return oAuthAppDO;
        }
    }

    /**
     * Get the tenant domain of an oauth application
     *
     * @param oAuthAppDO
     * @return
     */
    public static String getTenantDomainOfOauthApp(OAuthAppDO oAuthAppDO) {
        String tenantDomain = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        if (oAuthAppDO != null) {
            AuthenticatedUser appDeveloper = oAuthAppDO.getUser();
            tenantDomain = appDeveloper.getTenantDomain();
        }
        return tenantDomain;
    }

    public static class OAuthURL {

        public static String getOAuth1RequestTokenUrl() {
            String oauth1RequestTokenUrl = OAuthServerConfiguration.getInstance().getOAuth1RequestTokenUrl();
            if(StringUtils.isBlank(oauth1RequestTokenUrl)){
                oauth1RequestTokenUrl = IdentityUtil.getServerURL("oauth/request-token", true, true);
            }
            return oauth1RequestTokenUrl;
        }

        public static String getOAuth1AuthorizeUrl() {
            String oauth1AuthorizeUrl = OAuthServerConfiguration.getInstance().getOAuth1AuthorizeUrl();
            if(StringUtils.isBlank(oauth1AuthorizeUrl)){
                oauth1AuthorizeUrl = IdentityUtil.getServerURL("oauth/authorize-url", true, true);
            }
            return oauth1AuthorizeUrl;
        }

        public static String getOAuth1AccessTokenUrl() {
            String oauth1AccessTokenUrl = OAuthServerConfiguration.getInstance().getOAuth1AccessTokenUrl();
            if(StringUtils.isBlank(oauth1AccessTokenUrl)){
                oauth1AccessTokenUrl = IdentityUtil.getServerURL("oauth/access-token", true, true);
            }
            return oauth1AccessTokenUrl;
        }

        public static String getOAuth2AuthzEPUrl() {
            String oauth2AuthzEPUrl = OAuthServerConfiguration.getInstance().getOAuth2AuthzEPUrl();
            if(StringUtils.isBlank(oauth2AuthzEPUrl)){
                oauth2AuthzEPUrl = IdentityUtil.getServerURL("oauth2/authorize", true, false);
            }
            return oauth2AuthzEPUrl;
        }

        public static String getOAuth2TokenEPUrl() {
            String oauth2TokenEPUrl = OAuthServerConfiguration.getInstance().getOAuth2TokenEPUrl();
            if(StringUtils.isBlank(oauth2TokenEPUrl)){
                oauth2TokenEPUrl = IdentityUtil.getServerURL("oauth2/token", true, false);
            }
            return oauth2TokenEPUrl;
        }

        public static String getOAuth2UserInfoEPUrl() {
            String oauth2UserInfoEPUrl = OAuthServerConfiguration.getInstance().getOauth2UserInfoEPUrl();
            if(StringUtils.isBlank(oauth2UserInfoEPUrl)){
                oauth2UserInfoEPUrl = IdentityUtil.getServerURL("oauth2/userinfo", true, false);
            }
            return oauth2UserInfoEPUrl;
        }

        public static String getOIDCConsentPageUrl() {
            String OIDCConsentPageUrl = OAuthServerConfiguration.getInstance().getOIDCConsentPageUrl();
            if(StringUtils.isBlank(OIDCConsentPageUrl)){
                OIDCConsentPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_consent.do", false,
                        false);
            }
            return OIDCConsentPageUrl;
        }

        public static String getOAuth2ConsentPageUrl() {
            String oAuth2ConsentPageUrl = OAuthServerConfiguration.getInstance().getOauth2ConsentPageUrl();
            if(StringUtils.isBlank(oAuth2ConsentPageUrl)){
                oAuth2ConsentPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_authz.do", false,
                        false);
            }
            return oAuth2ConsentPageUrl;
        }

        public static String getOAuth2ErrorPageUrl() {
            String oAuth2ErrorPageUrl = OAuthServerConfiguration.getInstance().getOauth2ErrorPageUrl();
            if(StringUtils.isBlank(oAuth2ErrorPageUrl)){
                oAuth2ErrorPageUrl = IdentityUtil.getServerURL("/authenticationendpoint/oauth2_error.do", false, false);
            }
            return oAuth2ErrorPageUrl;
        }
    }

    public static boolean isOIDCAuthzRequest(Set<String> scope) {
        return scope.contains(OAuthConstants.Scope.OPENID);
    }

    public static boolean isOIDCAuthzRequest(String[] scope) {
        for(String openidscope : scope) {
            if (openidscope.equals(OAuthConstants.Scope.OPENID)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Util method to encrypt with old RSA algorithm
     * @param plainText
     * @return encrypted value
     * @throws IdentityOAuth2Exception
     */
    public static String encryptWithRSA(String plainText) throws IdentityOAuth2Exception {
        try {
            return CryptoUtil.getDefaultCryptoUtil().encryptAndBase64Encode(plainText.getBytes(Charsets.UTF_8),
                    "RSA", false);

        } catch (CryptoException e) {

            throw new IdentityOAuth2Exception("Error while encrypting ciphertext using RSA", e);
        }
    }

    /**
     * Method to check whether a encrypted value is in RSA+OAEP and wrapped with JSON format
     * When using EncryptionDecryptionPersistenceProcessor for oauth key encryption, if RSA+OAEP encryption
     * algorithm is enabled in carbon.properties file as 'org
     * .wso2.CipherTransformation=RSA/ECB/OAEPwithSHA1andMGF1Padding' CryptoUtil class will encrypt the oauth key
     * with RSA+OAEP algorithm and further will add some more metadata and wrap them in a JSON format.
     * Ex:
     * {
     * "c":"Npctne9G6K...noOOtVgE\u003d",
     * "t":"RSA/ECB/OAEPwithSHA1andMGF1Padding",
     * "tp":"6BF8E136EB36D4A56EA05C7AE4B9A45B63BF975D"
     * }
     * This method will check whether some encrypted value is in above format.It will be an indication that the value
     * is encrypted in the custom RSA+OAEP encryption with JSON wrapper.
     *
     * @param processedKey
     * @return boolean
     * @throws IdentityOAuth2Exception
     */
    public static boolean isSelfContainedCiphertext(String processedKey) throws IdentityOAuth2Exception {

        try {
            return CryptoUtil.getDefaultCryptoUtil().base64DecodeAndIsSelfContainedCipherText(processedKey);
        } catch (CryptoException e) {
            throw new IdentityOAuth2Exception("Error while checking for custom encryption", e);
        }
    }

    /**
     * Method to hash the client secret
     *
     * @param clientSecret
     * @return hashed client secret
     * @throws IdentityOAuth2Exception
     */
    public static String hashClientSecret(String clientSecret) throws IdentityOAuth2Exception {

        return new HashingPersistenceProcessor().getProcessedClientSecret(clientSecret);
    }

    /**
     * Method to hash the authorization code
     *
     * @param authzCode
     * @return hashed authorization code
     * @throws IdentityOAuth2Exception
     */
    public static String hashAuthzCode(String authzCode) throws IdentityOAuth2Exception {

        return new HashingPersistenceProcessor().getProcessedAuthzCode(authzCode);
    }

    /**
     * Method to hash the access token
     *
     * @param accessTokenIdentifier
     * @return hashed access token
     * @throws IdentityOAuth2Exception
     */
    public static String hashAccessTokenIdentifier(String accessTokenIdentifier) throws IdentityOAuth2Exception {

        return new HashingPersistenceProcessor().getProcessedAccessTokenIdentifier(accessTokenIdentifier);
    }

    /**
     * Method to hash the refresh token
     *
     * @param refreshToken
     * @return hashed refresh token
     * @throws IdentityOAuth2Exception
     */
    public static String hashRefreshToken(String refreshToken) throws IdentityOAuth2Exception {

        return new HashingPersistenceProcessor().getProcessedRefreshToken(refreshToken);
    }

    /**
     * Method to check whether RSA+OAEP encryption algorithm is enabled and EncryptionDecryptionPersistenceProcessor
     * is enabled in identity xml.
     * RSA + OAEP algorithm get enabled if carbon.properties file has following system property
     * org.wso2.CipherTransformation=RSA/ECB/OAEPwithSHA1andMGF1Padding
     *
     * @return true or false
     * @throws IdentityOAuth2Exception
     */
    public static boolean isEncryptionWithTransformationEnabled() throws IdentityOAuth2Exception {

        String cipherTransformation = System.getProperty(CIPHER_TRANSFORMATION_SYSTEM_PROPERTY);
        TokenPersistenceProcessor persistenceProcessor = OAuthServerConfiguration.getInstance()
                .getPersistenceProcessor();
        return cipherTransformation != null
                && (persistenceProcessor instanceof EncryptionDecryptionPersistenceProcessor);
    }

    /**
     * Method to check whether new columns with name ACCESS_TOKEN_HASH and REFRESH_TOKEN_HASH are created.
     * If oauth2 is using RSA+OAEP encryption algorithm it is must to have these two hash columns.
     * With the new encryption algorithm searching is done using hash.
     * As the encryption algorithm provides dynamic encryption values searching cannot be done with encrypted values.
     * Thus, using hashing.
     *
     * @return true if columns are available else return false
     * @throws IdentityOAuth2Exception
     */
    public static boolean isTokenHashColumnAvailable() throws IdentityOAuth2Exception {

        ResultSet resultSet = null;
        PreparedStatement preparedStatement = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        if (connection != null) {
            try {
                String sql;
                if (connection.getMetaData().getDriverName().contains("MySQL") || connection.getMetaData()
                        .getDriverName().contains("H2")) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_TABLE_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_TABLE_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL") || connection.getMetaData()
                        .getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_TABLE_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_TABLE_MYSQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_TABLE_INFORMIX;
                } else {
                    sql = SQLQueries.RETRIEVE_ACCESS_TOKEN_TABLE_ORACLE;
                }
                preparedStatement = connection.prepareStatement(sql);
                resultSet = preparedStatement.executeQuery();
                if (resultSet != null) {
                    //following statement will throw SQLException if the column is not found
                    resultSet.findColumn(ACCESS_TOKEN_HASH);
                    resultSet.findColumn(REFRESH_TOKEN_HASH);
                    //if we are here then the column exists, so token hashing is supported by the database.
                    return true;
                }
            } catch (SQLException e) {
                throw new IdentityOAuth2Exception(
                        "Error occurred while checking for columns: " + ACCESS_TOKEN_HASH + " and " + REFRESH_TOKEN_HASH
                                 + ". Required column " + ACCESS_TOKEN_HASH + " and " + REFRESH_TOKEN_HASH
                                + " missing.", e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
            }
        }
        return false;
    }

    /**
     * Method to check whether a column with name AUTHORIZATION_CODE_HASH is created.
     * If oauth2 is using RSA+OAEP encryption algorithm it is must to have this hash column.
     * With the new encryption algorithm searching is done using hash.
     * As the encryption algorithm provides dynamic encryption values searching cannot be done with encrypted values.
     * Thus, using hashing.
     *
     * @return true if column is available else return false
     * @throws IdentityOAuth2Exception
     */
    public static boolean isAuthzCodeHashColumnAvailable() throws IdentityOAuth2Exception {

        ResultSet resultSet = null;
        PreparedStatement preparedStatement = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        if (connection != null) {
            try {
                String sql;
                if (connection.getMetaData().getDriverName().contains("MySQL") || connection.getMetaData()
                        .getDriverName().contains("H2")) {
                    sql = SQLQueries.RETRIEVE_AUTHORIZATION_CODE_TABLE_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_AUTHORIZATION_CODE_TABLE_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL") || connection.getMetaData()
                        .getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_AUTHORIZATION_CODE_TABLE_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_AUTHORIZATION_CODE_TABLE_MYSQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_AUTHORIZATION_CODE_TABLE_INFORMIX;
                } else {
                    sql = SQLQueries.RETRIEVE_AUTHORIZATION_CODE_TABLE_ORACLE;
                }
                preparedStatement = connection.prepareStatement(sql);
                resultSet = preparedStatement.executeQuery();
                if (resultSet != null) {
                    //following statement will throw SQLException if the column is not found
                    resultSet.findColumn(AUTHORIZATION_CODE_HASH);
                    //if we are here then the column exists, so authorization code hashing is supported by the database.
                    return true;
                }
            } catch (SQLException e) {
                throw new IdentityOAuth2Exception(
                        "Error occurred while checking for columns: " + AUTHORIZATION_CODE_HASH + "." + "Required "
                                + "column " + AUTHORIZATION_CODE_HASH + " missing.", e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
            }
        }
        return false;
    }

    /**
     * Method to check whether a column with name CONSUMER_SECRET_HASH is created.
     * If oauth2 is using RSA+OAEP encryption algorithm it is must to have this hash column.
     * With the new encryption algorithm searching is done using hash.
     * As the encryption algorithm provides dynamic encryption values searching cannot be done with encrypted values.
     * Thus, using hashing.
     *
     * @return true if column is available else return false
     * @throws IdentityOAuth2Exception
     */
    public static boolean isConsumerSecretHashColumnAvailable() throws IdentityOAuth2Exception {

        ResultSet resultSet = null;
        PreparedStatement preparedStatement = null;
        Connection connection = IdentityDatabaseUtil.getDBConnection();
        if (connection != null) {
            try {
                String sql;
                if (connection.getMetaData().getDriverName().contains("MySQL") || connection.getMetaData()
                        .getDriverName().contains("H2")) {
                    sql = SQLQueries.RETRIEVE_CONSUMER_APPS_TABLE_MYSQL;
                } else if (connection.getMetaData().getDatabaseProductName().contains("DB2")) {
                    sql = SQLQueries.RETRIEVE_CONSUMER_APPS_TABLE_DB2SQL;
                } else if (connection.getMetaData().getDriverName().contains("MS SQL") || connection.getMetaData()
                        .getDriverName().contains("Microsoft")) {
                    sql = SQLQueries.RETRIEVE_CONSUMER_APPS_TABLE_MSSQL;
                } else if (connection.getMetaData().getDriverName().contains("PostgreSQL")) {
                    sql = SQLQueries.RETRIEVE_CONSUMER_APPS_TABLE_MYSQL;
                } else if (connection.getMetaData().getDriverName().contains("Informix")) {
                    // Driver name = "IBM Informix JDBC Driver for IBM Informix Dynamic Server"
                    sql = SQLQueries.RETRIEVE_CONSUMER_APPS_TABLE_INFORMIX;
                } else {
                    sql = SQLQueries.RETRIEVE_CONSUMER_APPS_TABLE_ORACLE;
                }
                preparedStatement = connection.prepareStatement(sql);
                resultSet = preparedStatement.executeQuery();
                if (resultSet != null) {
                    //following statement will throw SQLException if the column is not found
                    resultSet.findColumn(CONSUMER_SECRET_HASH);
                    //if we are here then the column exists, so consumer secret hashing is supported by the database.
                    return true;
                }
            } catch (SQLException e) {
                throw new IdentityOAuth2Exception(
                        "Error occurred while checking for columns: " + CONSUMER_SECRET_HASH + "." + "Required column "
                                + CONSUMER_SECRET_HASH + " missing.", e);
            } finally {
                IdentityDatabaseUtil.closeAllConnections(connection, resultSet, preparedStatement);
            }
        }
        return false;
    }

    /**
     * Method to check if columns to store access token hash, refresh token hash, consumer secret hash and
     * authorization code hash is available
     *
     * @return true or false
     * @throws IdentityOAuth2Exception
     */
    public static boolean isHashColumnsAvailable() throws IdentityOAuth2Exception {

        return isTokenHashColumnAvailable() && isAuthzCodeHashColumnAvailable() && isConsumerSecretHashColumnAvailable();
    }
}
