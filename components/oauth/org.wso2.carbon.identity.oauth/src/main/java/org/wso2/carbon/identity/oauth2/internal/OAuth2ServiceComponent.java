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

package org.wso2.carbon.identity.oauth2.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.eclipse.equinox.http.helper.ContextPathServletAdaptor;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.OAuth2Service;
import org.wso2.carbon.identity.oauth2.OAuth2TokenValidationService;
import org.wso2.carbon.identity.oauth2.util.OAuth2Util;
import org.wso2.carbon.identity.openidconnect.session.servlet.OIDCLogoutServlet;
import org.wso2.carbon.identity.openidconnect.session.servlet.OIDCSessionIFrameServlet;
import org.wso2.carbon.identity.user.store.configuration.listener.UserStoreConfigListener;
import org.wso2.carbon.stratos.common.listeners.TenantMgtListener;

import javax.servlet.Servlet;

/**
 * @scr.component name="identity.oauth2.component" immediate="true"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 * @scr.reference name="identity.application.management.component"
 * interface=
 * "org.wso2.carbon.identity.application.mgt.ApplicationManagementService"
 * cardinality="1..1" policy="dynamic"
 * bind="setApplicationMgtService"
 * unbind="unsetApplicationMgtService"
 * @scr.reference name="identityCoreInitializedEventService"
 * interface="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent" cardinality="1..1"
 * policy="dynamic" bind="setIdentityCoreInitializedEventService" unbind="unsetIdentityCoreInitializedEventService"
 */
public class OAuth2ServiceComponent {
    private static Log log = LogFactory.getLog(OAuth2ServiceComponent.class);
    private static BundleContext bundleContext;
    private HttpService httpService;

    protected void activate(ComponentContext context) {
        try {
            if ((OAuth2Util.isEncryptionWithTransformationEnabled() && !OAuth2Util.isHashColumnsAvailable())) {
                throw new IdentityOAuth2Exception("Error occurred while checking for RSA OAEP encryption. Please "
                        + "check whether RSA+OAEP is enabled, EncryptionDecryptionPersistenceProcessor is enabled and "
                        + "necessary hash columns are created.");
            }
            //Registering OAuth2Service as a OSGIService
            bundleContext = context.getBundleContext();
            bundleContext.registerService(OAuth2Service.class.getName(), new OAuth2Service(), null);
            // exposing server configuration as a service
            OAuthServerConfiguration oauthServerConfig = OAuthServerConfiguration.getInstance();
            bundleContext.registerService(OAuthServerConfiguration.class.getName(), oauthServerConfig, null);
            OAuth2TokenValidationService tokenValidationService = new OAuth2TokenValidationService();
            bundleContext.registerService(OAuth2TokenValidationService.class.getName(), tokenValidationService, null);
            if (log.isDebugEnabled()) {
                log.debug("Identity OAuth bundle is activated");
            }

            ServiceRegistration tenantMgtListenerSR = bundleContext
                    .registerService(TenantMgtListener.class.getName(), new OAuthTenantMgtListenerImpl(), null);
            if (tenantMgtListenerSR != null) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth - TenantMgtListener registered.");
                }
            } else {
                log.error("OAuth - TenantMgtListener could not be registered.");
            }

            ServiceRegistration userStoreConfigEventSR = bundleContext
                    .registerService(UserStoreConfigListener.class.getName(), new OAuthUserStoreConfigListenerImpl(),
                            null);
            if (userStoreConfigEventSR != null) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth - UserStoreConfigListener registered.");
                }
            } else {
                log.error("OAuth - UserStoreConfigListener could not be registered.");
            }

            ServiceRegistration oauthApplicationMgtListenerSR = bundleContext
                    .registerService(ApplicationMgtListener.class.getName(), new OAuthApplicationMgtListener(), null);
            if (oauthApplicationMgtListenerSR != null) {
                if (log.isDebugEnabled()) {
                    log.debug("OAuth - ApplicationMgtListener registered.");
                }
            } else {
                log.error("OAuth - ApplicationMgtListener could not be registered.");
            }
            registerOIDCServlets();

        } catch (IdentityOAuth2Exception e) {
            String errorMessage = "Error occurred while checking for RSA OAEP encryption";
            log.error(errorMessage, e);
        }

    }

    /**
     * Set Application management service implementation
     *
     * @param applicationMgtService Application management service
     */
    protected void setApplicationMgtService(ApplicationManagementService applicationMgtService) {
        if (log.isDebugEnabled()) {
            log.debug("ApplicationManagementService set in Identity OAuth2ServiceComponent bundle");
        }
        OAuth2ServiceComponentHolder.setApplicationMgtService(applicationMgtService);
    }

    /**
     * Unset Application management service implementation
     *
     * @param applicationMgtService Application management service
     */
    protected void unsetApplicationMgtService(ApplicationManagementService applicationMgtService) {
        if (log.isDebugEnabled()) {
            log.debug("ApplicationManagementService unset in Identity OAuth2ServiceComponent bundle");
        }
        OAuth2ServiceComponentHolder.setApplicationMgtService(null);
    }

    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void setHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.info("Setting the HTTP Service.");
        }
        this.httpService = httpService;
    }

    protected void unsetHttpService(HttpService httpService) {

        if (log.isDebugEnabled()) {
            log.info("Unsetting the HTTP Service.");
        }
    }

    /**
     * Registers servlets related to OIDC session management.
     */
    private void registerOIDCServlets() {

        // Register Session IFrame Servlet
        Servlet sessionIFrameServlet = new ContextPathServletAdaptor(new OIDCSessionIFrameServlet(), "/oidc/checksession");
        try {
            httpService.registerServlet("/oidc/checksession", sessionIFrameServlet, null, null);
        } catch (Exception e) {
            String msg = "Error when registering OIDC Session IFrame Servlet via the HttpService.";
            log.error(msg, e);
            throw new RuntimeException(msg, e);
        }

        // Register OIDC logout servlet.
        Servlet logoutServlet = new ContextPathServletAdaptor(new OIDCLogoutServlet(), "/oidc/logout");
        try {
            httpService.registerServlet("/oidc/logout", logoutServlet, null, null);
        } catch (Exception e) {
            String msg = "Error when registering OIDC Logout Servlet via the HttpService.";
            log.error(msg, e);
            throw new RuntimeException(msg, e);
        }
    }
}
