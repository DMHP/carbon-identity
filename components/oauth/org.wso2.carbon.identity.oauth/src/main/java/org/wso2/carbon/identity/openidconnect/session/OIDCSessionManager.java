/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.openidconnect.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.openidconnect.session.cache.OIDCSessionParticipantCache;
import org.wso2.carbon.identity.openidconnect.session.cache.OIDCSessionParticipantCacheEntry;
import org.wso2.carbon.identity.openidconnect.session.cache.OIDCSessionParticipantCacheKey;

/**
 * This class provides session state CRUD operations
 */
public class OIDCSessionManager {

    private static final Log log = LogFactory.getLog(OIDCSessionManager.class);

    /**
     * Stores the session state against the provided session id
     *
     * @param sessionId session id value
     * @param sessionState OIDCSessionState instance
     */
    public void storeOIDCSessionState(String sessionId, OIDCSessionState sessionState) {

        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCacheEntry cacheEntry = new OIDCSessionParticipantCacheEntry();
        cacheEntry.setSessionState(sessionState);

        if(log.isDebugEnabled()){
            log.debug(String.format("Storing the OIDC session state against the session id ('%s' cookie value) '%s'",
                    OIDCSessionConstants.OPBS_COOKIE_ID, sessionId));
        }

        OIDCSessionParticipantCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    /**
     * Retrieves session state for the given session id
     *
     * @param sessionId session id value
     * @return OIDCSessionState instance
     */
    public OIDCSessionState getOIDCSessionState(String sessionId) {

        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCacheEntry cacheEntry = OIDCSessionParticipantCache.getInstance().getValueFromCache
                (cacheKey);

        if(cacheEntry == null){
            if(log.isDebugEnabled()){
                log.debug(String.format("OIDC session state is NOT available for the session id ('%s' cookie value) '%s'.",
                        OIDCSessionConstants.OPBS_COOKIE_ID, sessionId));
            }
            return null;
        }else{
            if(log.isDebugEnabled()){
                log.debug(String.format("OIDC session state is available for the session id ('%s' cookie value) '%s'.",
                        OIDCSessionConstants.OPBS_COOKIE_ID, sessionId));
            }

            return cacheEntry.getSessionState();
        }

    }

    /**
     * Removes the session against the old session id and restore against the provided new session id
     *
     * @param oldSessionId
     * @param newSessionId
     * @param sessionState
     */
    public void restoreOIDCSessionState(String oldSessionId, String newSessionId, OIDCSessionState sessionState) {

        if(log.isDebugEnabled()){
            log.debug(String.format("Restoring the session state for the session id ('%s' cookie value) " +
                            "'%s' with a new session id '%s'",
                    OIDCSessionConstants.OPBS_COOKIE_ID, oldSessionId, newSessionId));
        }

        removeOIDCSessionState(oldSessionId);
        storeOIDCSessionState(newSessionId, sessionState);
    }

    /**
     * Removes the session against the given session id
     *
     * @param sessionId session id value
     */
    public void removeOIDCSessionState(String sessionId) {

        if(log.isDebugEnabled()){
            log.debug(String.format("Removing the session state for the session id ('%s' cookie value) '%s'",
                    OIDCSessionConstants.OPBS_COOKIE_ID, sessionId));
        }

        OIDCSessionParticipantCacheKey cacheKey = new OIDCSessionParticipantCacheKey();
        cacheKey.setSessionID(sessionId);

        OIDCSessionParticipantCache.getInstance().clearCacheEntry(cacheKey);
    }

    /**
     * Checks if there is a session exists for the gives session id
     *
     * @param sessionId session id value
     * @return true if session exists
     */
    public boolean sessionExists(String sessionId) {
        return getOIDCSessionState(sessionId) != null;
    }
}
