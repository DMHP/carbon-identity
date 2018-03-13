/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.samlsso.manager;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.xerces.impl.Constants;
import org.apache.xerces.util.SecurityManager;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.IdResolver;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.common.SignableSAMLObject;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.common.Extensions;
import org.opensaml.saml2.common.impl.ExtensionsBuilder;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.EncryptedAssertion;
import org.opensaml.saml2.core.Issuer;
import org.opensaml.saml2.core.LogoutRequest;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.NameIDPolicy;
import org.opensaml.saml2.core.NameIDType;
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml2.core.Response;
import org.opensaml.saml2.core.SessionIndex;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnRequestBuilder;
import org.opensaml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml2.core.impl.LogoutRequestBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.NameIDPolicyBuilder;
import org.opensaml.saml2.core.impl.RequestedAuthnContextBuilder;
import org.opensaml.saml2.core.impl.SessionIndexBuilder;
import org.opensaml.saml2.encryption.Decrypter;
import org.opensaml.security.SAMLSignatureProfileValidator;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.io.Unmarshaller;
import org.opensaml.xml.io.UnmarshallerFactory;
import org.opensaml.xml.io.UnmarshallingException;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.security.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xml.security.keyinfo.StaticKeyInfoCredentialResolver;
import org.opensaml.xml.security.x509.X509Credential;
import org.opensaml.xml.signature.SignatureValidator;
import org.opensaml.xml.signature.impl.SignatureImpl;
import org.opensaml.xml.util.Base64;
import org.opensaml.xml.util.DatatypeHelper;
import org.opensaml.xml.util.XMLHelper;
import org.opensaml.xml.validation.ValidationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.wso2.carbon.CarbonConstants;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.exception.SAMLSSOException;
import org.wso2.carbon.identity.application.authenticator.samlsso.internal.SAMLSSOAuthenticatorServiceComponent;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.CarbonEntityResolver;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOConstants;
import org.wso2.carbon.identity.application.authenticator.samlsso.util.SSOUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.user.api.UserRealm;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.core.UserStoreManager;
import org.xml.sax.SAXException;

import javax.crypto.SecretKey;
import javax.servlet.http.HttpServletRequest;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class DefaultSAML2SSOManager implements SAML2SSOManager {

    private static final String SECURITY_MANAGER_PROPERTY = Constants.XERCES_PROPERTY_PREFIX +
            Constants.SECURITY_MANAGER_PROPERTY;
    private static final int ENTITY_EXPANSION_LIMIT = 0;
    private static final String SIGN_AUTH2_SAML_USING_SUPER_TENANT = "SignAuth2SAMLUsingSuperTenant";
    private static final String NAMEID_TYPE = "NameIDType";
    private static final String NAMEID_SP_NAME_QUALIFIER = "NameIDSPNameQualifier";
    private static Log log = LogFactory.getLog(DefaultSAML2SSOManager.class);
    private static Log AUDIT_LOG = CarbonConstants.AUDIT_LOG;
    private static boolean bootStrapped = false;
    private static String DEFAULT_MULTI_ATTRIBUTE_SEPARATOR = ",";
    private static String MULTI_ATTRIBUTE_SEPARATOR = "MultiAttributeSeparator";
    private IdentityProvider identityProvider = null;
    private Map<String, String> properties;
    private String tenantDomain;

    // Parameter constants introduced for Assertion Validity Period Verification
    private static final String VERIFY_ASSERTION_VALIDITY_PERIOD = "VerifyAssertionValidityPeriod";
    private static final String TIME_STAMP_SKEW = "TimestampSkew";
    // Instance variable that defines default Time Stamp Skew Value
    private int timeStampSkewInSeconds = 300;

    @Override
    public void init(String tenantDomain, Map<String, String> properties, IdentityProvider idp)
            throws SAMLSSOException {

        this.tenantDomain = tenantDomain;
        this.identityProvider = idp;
        this.properties = properties;
    }

    /**
     * Returns the redirection URL with the appended SAML2
     * Request message
     *
     * @param request SAML 2 request
     * @return redirectionUrl
     */
    @Override
    public String buildRequest(HttpServletRequest request, boolean isLogout, boolean isPassive,
                               String loginPage, AuthenticationContext context)
            throws SAMLSSOException {

        String contextIdentifier = context.getContextIdentifier();
        RequestAbstractType requestMessage;

        if (request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ) == null) {
            String queryParam = context.getQueryParams();
            if (queryParam != null) {
                String[] params = queryParam.split("&");
                for (String param : params) {
                    String[] values = param.split("=");
                    if (values.length == 2 && SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ.equals(values[0])) {
                            request.setAttribute(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ, values[1]);
                            break;
                        }
                }
            }
        }

        if (!isLogout) {
            requestMessage = buildAuthnRequest(request, isPassive, loginPage, context);
        } else {
            String username = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_USERNAME);
            String sessionIndex = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_SESSION_INDEX);
            String nameQualifier = (String) request.getSession().getAttribute(SSOConstants.NAME_QUALIFIER);
            String spNameQualifier = (String) request.getSession().getAttribute(SSOConstants.SP_NAME_QUALIFIER);

            requestMessage = buildLogoutRequest(username, sessionIndex, loginPage, nameQualifier, spNameQualifier);
        }
        String idpUrl = null;
        boolean isSignAuth2SAMLUsingSuperTenant = false;

        String encodedRequestMessage = encodeRequestMessage(requestMessage);
        StringBuilder httpQueryString = new StringBuilder("SAMLRequest=" + encodedRequestMessage);

        try {
            httpQueryString.append("&RelayState=" + URLEncoder.encode(contextIdentifier, "UTF-8").trim());
        } catch (UnsupportedEncodingException e) {
            throw new SAMLSSOException("Error occurred while url encoding RelayState", e);
        }

        if (SSOUtils.isAuthnRequestSigned(properties)) {
			String signatureAlgoProp = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
            if (StringUtils.isEmpty(signatureAlgoProp)) {
                signatureAlgoProp = IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1;
            }
            String signatureAlgo = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms()
                    .get(signatureAlgoProp);

            Map<String, String> parameterMap = FileBasedConfigurationBuilder.getInstance()
                    .getAuthenticatorBean(SSOConstants.AUTHENTICATOR_NAME).getParameterMap();
            if (parameterMap.size() > 0) {
                isSignAuth2SAMLUsingSuperTenant = Boolean.parseBoolean(parameterMap.
                        get(SIGN_AUTH2_SAML_USING_SUPER_TENANT));
            }
            if (isSignAuth2SAMLUsingSuperTenant) {
				SSOUtils.addSignatureToHTTPQueryString(httpQueryString, signatureAlgo,
                    new X509CredentialImpl(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME, null));
            } else {
                SSOUtils.addSignatureToHTTPQueryString(httpQueryString, signatureAlgo,
                    new X509CredentialImpl(context.getTenantDomain(), null));
            }
        }	
        if (loginPage.indexOf("?") > -1) {
            idpUrl = loginPage.concat("&").concat(httpQueryString.toString());
        } else {
            idpUrl = loginPage.concat("?").concat(httpQueryString.toString());
        }
        return idpUrl;
    }


    /**
     * @param request
     * @param isLogout
     * @param isPassive
     * @param loginPage
     * @return return encoded SAML Auth request
     * @throws SAMLSSOException
     */
    public String buildPostRequest(HttpServletRequest request, boolean isLogout,
                                   boolean isPassive, String loginPage, AuthenticationContext context) throws SAMLSSOException {

        RequestAbstractType requestMessage;
        String signatureAlgoProp = null;
        String digestAlgoProp = null;
        String includeCertProp = null;
        String signatureAlgo = null;
        String digestAlgo = null;
        boolean includeCert = false;
        
        // get Signature Algorithm
        signatureAlgoProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.SIGNATURE_ALGORITHM);
        if (StringUtils.isEmpty(signatureAlgoProp)) {
            signatureAlgoProp = IdentityApplicationConstants.XML.SignatureAlgorithm.RSA_SHA1;
        }
        signatureAlgo = IdentityApplicationManagementUtil.getXMLSignatureAlgorithms().get(signatureAlgoProp);
        
        // get Digest Algorithm
        digestAlgoProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.DIGEST_ALGORITHM);
        if (StringUtils.isEmpty(digestAlgoProp)) {
            digestAlgoProp = IdentityApplicationConstants.XML.DigestAlgorithm.SHA1;
        }
        digestAlgo = IdentityApplicationManagementUtil.getXMLDigestAlgorithms().get(digestAlgoProp);
        
        includeCertProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_CERT);
        if (StringUtils.isEmpty(includeCertProp) || Boolean.parseBoolean(includeCertProp)) {
            includeCert = true;
        }

        if (!isLogout) {
            requestMessage = buildAuthnRequest(request, isPassive, loginPage, context);
            if (SSOUtils.isAuthnRequestSigned(properties)) {
                SSOUtils.setSignature(requestMessage, signatureAlgo, digestAlgo, includeCert,
                        new X509CredentialImpl(context.getTenantDomain(), null));
            }
        } else {
            String username = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_USERNAME);
            String sessionIndex = (String) request.getSession().getAttribute(SSOConstants.LOGOUT_SESSION_INDEX);
            String nameQualifier = (String) request.getSession().getAttribute(SSOConstants.NAME_QUALIFIER);
            String spNameQualifier = (String) request.getSession().getAttribute(SSOConstants.SP_NAME_QUALIFIER);

            requestMessage = buildLogoutRequest(username, sessionIndex, loginPage, nameQualifier, spNameQualifier);
            if (SSOUtils.isLogoutRequestSigned(properties)) {
                SSOUtils.setSignature(requestMessage, signatureAlgo, digestAlgo, includeCert,
                        new X509CredentialImpl(context.getTenantDomain(), null));
            }
        }

        return SSOUtils.encode(SSOUtils.marshall(requestMessage));
    }

    @Override
    public void processResponse(HttpServletRequest request) throws SAMLSSOException {

        String decodedResponse = new String(Base64.decode(request.getParameter(
                SSOConstants.HTTP_POST_PARAM_SAML2_RESP)));
        XMLObject samlObject = unmarshall(decodedResponse);
        if (samlObject instanceof LogoutResponse) {
            //This is a SAML response for a single logout request from the SP
            doSLO(request);
        } else {
            processSSOResponse(request);
        }
    }
    
    protected AuthnRequest getAuthnRequest(AuthenticationContext context) throws SAMLSSOException {

        AuthnRequest authnRequest = null;
        AuthenticationRequest authenticationRequest = context.getAuthenticationRequest();
        String[] samlRequestParams = authenticationRequest
                .getRequestQueryParam(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ);
        String samlRequest = null;
        if (samlRequestParams != null && samlRequestParams.length > 0) {
            samlRequest = samlRequestParams[0];
            XMLObject xmlObject;
            if (authenticationRequest.isPost()) {
                xmlObject = unmarshall(SSOUtils.decodeForPost(samlRequest));
            } else {
                xmlObject = unmarshall(SSOUtils.decode(samlRequest));
            }
            if (xmlObject instanceof AuthnRequest) {
                authnRequest = (AuthnRequest) xmlObject;
            }
        }
        return authnRequest;
    }

    protected Extensions getSAMLExtensions(HttpServletRequest request) {

        try {
            String samlRequest = request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ);
            if (samlRequest == null) {
                samlRequest = (String) request.getAttribute(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ);
            }

            if (samlRequest != null) {
                XMLObject xmlObject;
                if (SSOConstants.HTTP_POST.equals(request.getMethod())) {
                    xmlObject = unmarshall(SSOUtils.decodeForPost(samlRequest));
                } else {
                    xmlObject = unmarshall(SSOUtils.decode(samlRequest));
                }
                if (xmlObject instanceof AuthnRequest) {
                    AuthnRequest authnRequest = (AuthnRequest) xmlObject;
                    Extensions oldExtensions = authnRequest.getExtensions();
                    if (oldExtensions != null) {
                        ExtensionsBuilder extBuilder = new ExtensionsBuilder();
                        Extensions extensions = extBuilder.buildObject(SAMLConstants.SAML20P_NS,
                                Extensions.LOCAL_NAME, SAMLConstants.SAML20P_PREFIX);
                        extensions.setDOM(oldExtensions.getDOM());
                        return extensions;
                    }
                }
            }
        } catch (Exception e) { // TODO IDENTITY-2421
            //ignore
            log.debug("Error while loading SAML Extensions", e);
        }

        return null;
    }
    
    protected Extensions getSAMLExtensions(AuthnRequest inboundAuthnRequest) {
        
        Extensions extensions = null;
        Extensions oldExtensions = inboundAuthnRequest.getExtensions();
        if (oldExtensions != null) {
            ExtensionsBuilder extBuilder = new ExtensionsBuilder();
            extensions = extBuilder.buildObject(SAMLConstants.SAML20P_NS,
                    Extensions.LOCAL_NAME, SAMLConstants.SAML20P_PREFIX);
            extensions.setDOM(oldExtensions.getDOM());
        }
        return extensions;
    }

    /**
     * This method handles the logout requests from the IdP
     * Any request for the defined logout URL is handled here
     *
     * @param request
     * @throws javax.servlet.ServletException
     * @throws IOException
     */
    public void doSLO(HttpServletRequest request) throws SAMLSSOException {
        XMLObject samlObject = null;
        if (request.getParameter(SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ) != null) {
            samlObject = unmarshall(new String(Base64.decode(request.getParameter(
                    SSOConstants.HTTP_POST_PARAM_SAML2_AUTH_REQ))));
        }
        if (samlObject == null) {
            samlObject = unmarshall(new String(Base64.decode(request.getParameter(
                    SSOConstants.HTTP_POST_PARAM_SAML2_RESP))));
        }
        if (samlObject instanceof LogoutRequest) {
            LogoutRequest logoutRequest = (LogoutRequest) samlObject;
            String sessionIndex = logoutRequest.getSessionIndexes().get(0).getSessionIndex();
        } else if (samlObject instanceof LogoutResponse) {
            request.getSession().invalidate();
        } else {
            throw new SAMLSSOException("Invalid Single Logout SAML Request");
        }
    }

    private void processSSOResponse(HttpServletRequest request) throws SAMLSSOException {

        Response samlResponse = (Response) unmarshall(new String(Base64.decode(request.getParameter(
                SSOConstants.HTTP_POST_PARAM_SAML2_RESP))));

        Assertion assertion = null;

        if (SSOUtils.isAssertionEncryptionEnabled(properties)) {
            List<EncryptedAssertion> encryptedAssertions = samlResponse.getEncryptedAssertions();
            EncryptedAssertion encryptedAssertion = null;
            if (CollectionUtils.isNotEmpty(encryptedAssertions)) {
                encryptedAssertion = encryptedAssertions.get(0);
                try {
                    assertion = getDecryptedAssertion(encryptedAssertion);
                } catch (Exception e) {
                    throw new SAMLSSOException("Unable to decrypt the SAML Assertion", e);
                }
            }
        } else {
            List<Assertion> assertions = samlResponse.getAssertions();
            if (CollectionUtils.isNotEmpty(assertions)) {
                assertion = assertions.get(0);
            }
        }

        if (assertion == null) {
            if (samlResponse.getStatus() != null &&
                    samlResponse.getStatus().getStatusCode() != null &&
                    samlResponse.getStatus().getStatusCode().getValue().equals(
                            SSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR) &&
                    samlResponse.getStatus().getStatusCode().getStatusCode() != null &&
                    samlResponse.getStatus().getStatusCode().getStatusCode().getValue().equals(
                            SSOConstants.StatusCodes.NO_PASSIVE)) {
                return;
            }
            throw new SAMLSSOException("SAML Assertion not found in the Response");
        }

        // validate the assertion validity period
        validateAssertionValidityPeriod(assertion);

        // validate audience restriction
        validateAudienceRestriction(assertion);

        // validate signature this SP only looking for assertion signature
        validateSignature(samlResponse, assertion);

        // Get the subject name from the Response Object and forward it to login_action.jsp
        String subject = null;
        String nameQualifier = null;
        String spNameQualifier = null;
        if (assertion.getSubject() != null && assertion.getSubject().getNameID() != null) {
            subject = assertion.getSubject().getNameID().getValue();
        }

        if (subject == null) {
            throw new SAMLSSOException("SAML Response does not contain the name of the subject");
        }

        request.getSession().setAttribute("username", subject); // get the subject
        nameQualifier = assertion.getSubject().getNameID().getNameQualifier();
        spNameQualifier = assertion.getSubject().getNameID().getSPNameQualifier();

        request.getSession(false).setAttribute("samlssoAttributes", getAssertionStatements(assertion));

        if (assertion.getAuthnStatements() != null) {
            List<String> authnContextClassRefs = new ArrayList<>();
            for (AuthnStatement authnStatement : assertion.getAuthnStatements()) {
                if (authnStatement.getAuthnContext() != null
                        && authnStatement.getAuthnContext().getAuthnContextClassRef() != null
                        && StringUtils.isNotBlank(authnStatement.getAuthnContext().getAuthnContextClassRef()
                        .getAuthnContextClassRef())) {
                    if (log.isDebugEnabled()) {
                        log.debug("Received AuthnContextClassRef: " + authnStatement.getAuthnContext()
                                .getAuthnContextClassRef().getAuthnContextClassRef());
                    }
                    authnContextClassRefs.add(authnStatement.getAuthnContext().getAuthnContextClassRef()
                            .getAuthnContextClassRef());
                }
            }

            if (!authnContextClassRefs.isEmpty()) {
                Map<String, Object> authnContextClassRefMap = new HashMap<>();
                authnContextClassRefMap.put(SSOConstants.PASS_THROUGH_DATA_TYPE, SSOConstants.AUTHN_CONTEXT_CLASS_REF);
                authnContextClassRefMap.put(SSOConstants.PASS_THROUGH_DATA, authnContextClassRefs);
                authnContextClassRefMap.put(IdentityApplicationConstants.Authenticator.SAML2SSO.IDP_ENTITY_ID,
                        assertion.getIssuer().getValue());
                request.getSession().setAttribute(SSOConstants.AUTHN_CONTEXT_CLASS_REF, authnContextClassRefMap);
            }
        }

        //For removing the session when the single sign out request made by the SP itself
        if (SSOUtils.isLogoutEnabled(properties)) {
            String sessionId = assertion.getAuthnStatements().get(0).getSessionIndex();
            if (sessionId == null) {
                throw new SAMLSSOException("Single Logout is enabled but IdP Session ID not found in SAML Assertion");
            }
            request.getSession().setAttribute(SSOConstants.IDP_SESSION, sessionId);
            request.getSession().setAttribute(SSOConstants.LOGOUT_USERNAME, nameQualifier);
            request.getSession().setAttribute(SSOConstants.SP_NAME_QUALIFIER, spNameQualifier);
        }

    }

    private LogoutRequest buildLogoutRequest(String user, String sessionIndexStr, String idpUrl, String nameQualifier, String spNameQualifier)
            throws SAMLSSOException {

        LogoutRequest logoutReq = new LogoutRequestBuilder().buildObject();

        logoutReq.setID(SSOUtils.createID());
        logoutReq.setDestination(idpUrl);

        DateTime issueInstant = new DateTime();
        logoutReq.setIssueInstant(issueInstant);
        logoutReq.setNotOnOrAfter(new DateTime(issueInstant.getMillis() + 5 * 60 * 1000));

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject();

        String spEntityId = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID);

        if (spEntityId != null && !spEntityId.isEmpty()) {
            issuer.setValue(spEntityId);
        } else {
            issuer.setValue("carbonServer");
        }

        logoutReq.setIssuer(issuer);

        NameID nameId = new NameIDBuilder().buildObject();
        nameId.setFormat(NameIDType.UNSPECIFIED);
        nameId.setValue(user);
        nameId.setNameQualifier(nameQualifier);
        nameId.setSPNameQualifier(spNameQualifier);
        logoutReq.setNameID(nameId);

        SessionIndex sessionIndex = new SessionIndexBuilder().buildObject();

        if (sessionIndexStr != null) {
            sessionIndex.setSessionIndex(sessionIndexStr);
        } else {
            sessionIndex.setSessionIndex(UUID.randomUUID().toString());
        }

        logoutReq.getSessionIndexes().add(sessionIndex);
        logoutReq.setReason("Single Logout");

        return logoutReq;
    }

    private AuthnRequest buildAuthnRequest(HttpServletRequest request,
                                           boolean isPassive, String idpUrl, AuthenticationContext context) throws SAMLSSOException {

        IssuerBuilder issuerBuilder = new IssuerBuilder();
        Issuer issuer = issuerBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:assertion", "Issuer", "samlp");

        String spEntityId = properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID);

        if (spEntityId != null && !spEntityId.isEmpty()) {
            issuer.setValue(spEntityId);
        } else {
            issuer.setValue("carbonServer");
        }

        DateTime issueInstant = new DateTime();

		/* Creation of AuthRequestObject */
        AuthnRequestBuilder authRequestBuilder = new AuthnRequestBuilder();
        AuthnRequest authRequest = authRequestBuilder.buildObject("urn:oasis:names:tc:SAML:2.0:protocol",
                "AuthnRequest", "samlp");
        authRequest.setForceAuthn(isForceAuthenticate(context));
        authRequest.setIsPassive(isPassive);
        authRequest.setIssueInstant(issueInstant);

		String includeProtocolBindingProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_PROTOCOL_BINDING);
        if (StringUtils.isEmpty(includeProtocolBindingProp) || Boolean.parseBoolean(includeProtocolBindingProp)) {
            authRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
        }

        String acsUrl = null;
        AuthenticatorConfig authenticatorConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap()
                        .get(SSOConstants.AUTHENTICATOR_NAME);
        if (authenticatorConfig != null){
            String tmpAcsUrl = authenticatorConfig.getParameterMap().get(SSOConstants.ServerConfig.SAML_SSO_ACS_URL);
            if(StringUtils.isNotBlank(tmpAcsUrl)){
                acsUrl = tmpAcsUrl;
            }
        }

        if(acsUrl == null) {
            acsUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        }

        authRequest.setAssertionConsumerServiceURL(acsUrl);
        authRequest.setIssuer(issuer);
        authRequest.setID(SSOUtils.createID());
        authRequest.setVersion(SAMLVersion.VERSION_20);
        authRequest.setDestination(idpUrl);

		String attributeConsumingServiceIndexProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.ATTRIBUTE_CONSUMING_SERVICE_INDEX);
        if (StringUtils.isNotEmpty(attributeConsumingServiceIndexProp)) {
            try {	
                authRequest.setAttributeConsumingServiceIndex(Integer
                        .valueOf(attributeConsumingServiceIndexProp));
            } catch (NumberFormatException e) {
                log.error(
                        "Error while populating SAMLRequest with AttributeConsumingServiceIndex: "
                                + attributeConsumingServiceIndexProp, e);
            }
        }
        
        String includeNameIDPolicyProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_NAME_ID_POLICY);
        if (StringUtils.isEmpty(includeNameIDPolicyProp) || Boolean.parseBoolean(includeNameIDPolicyProp)) {
            String nameIDType = properties.get(NAMEID_TYPE);
            String nameIDSPNameQualifier = properties.get(NAMEID_SP_NAME_QUALIFIER);
            NameIDPolicyBuilder nameIdPolicyBuilder = new NameIDPolicyBuilder();
            NameIDPolicy nameIdPolicy = nameIdPolicyBuilder.buildObject();
            if (StringUtils.isNotBlank(nameIDType)) {
                nameIdPolicy.setFormat(nameIDType);
            } else {
                nameIdPolicy.setFormat(NameIDType.UNSPECIFIED);
            }
            if (StringUtils.isNotBlank(nameIDSPNameQualifier)) {
                nameIdPolicy.setSPNameQualifier(nameIDSPNameQualifier);
            }
            //nameIdPolicy.setSPNameQualifier(issuer);
            nameIdPolicy.setAllowCreate(true);
            authRequest.setNameIDPolicy(nameIdPolicy);
        }
		
		//Get the inbound SAMLRequest
        AuthnRequest inboundAuthnRequest = getAuthnRequest(context);
        
        RequestedAuthnContext requestedAuthnContext = buildRequestedAuthnContext(inboundAuthnRequest);
        if (requestedAuthnContext != null) {
            authRequest.setRequestedAuthnContext(requestedAuthnContext);
        }

        Extensions extensions = getSAMLExtensions(request);
        if (extensions != null) {
            authRequest.setExtensions(extensions);
        }

        return authRequest;
    }
    
    private RequestedAuthnContext buildRequestedAuthnContext(AuthnRequest inboundAuthnRequest) throws SAMLSSOException {
        
        /* AuthnContext */
        RequestedAuthnContextBuilder requestedAuthnContextBuilder = null;
        RequestedAuthnContext requestedAuthnContext = null;
        
        String includeAuthnContext = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.INCLUDE_AUTHN_CONTEXT);
        
        if (StringUtils.isNotEmpty(includeAuthnContext) && "as_request".equalsIgnoreCase(includeAuthnContext)) {
            if (inboundAuthnRequest != null) {
                RequestedAuthnContext incomingRequestedAuthnContext = inboundAuthnRequest.getRequestedAuthnContext();
                if (incomingRequestedAuthnContext != null) {
                    requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
                    requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
                    requestedAuthnContext.setDOM(incomingRequestedAuthnContext.getDOM());
                }
            }
        } else if (StringUtils.isEmpty(includeAuthnContext) || "yes".equalsIgnoreCase(includeAuthnContext)) {
            requestedAuthnContextBuilder = new RequestedAuthnContextBuilder();
            requestedAuthnContext = requestedAuthnContextBuilder.buildObject();
            /* AuthnContextClass */
            AuthnContextClassRefBuilder authnContextClassRefBuilder = new AuthnContextClassRefBuilder();
            AuthnContextClassRef authnContextClassRef = authnContextClassRefBuilder
                    .buildObject(SAMLConstants.SAML20_NS,
                            AuthnContextClassRef.DEFAULT_ELEMENT_LOCAL_NAME,
                            SAMLConstants.SAML20_PREFIX);

            String authnContextClass = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_CLASS);

            if (StringUtils.isNotEmpty(authnContextClass)) {
                String samlAuthnContextURN = IdentityApplicationManagementUtil
                        .getSAMLAuthnContextClasses().get(authnContextClass);
                if(!StringUtils.isBlank(samlAuthnContextURN)){
                    //There was one matched URN for give authnContextClass.
                    authnContextClassRef.setAuthnContextClassRef(samlAuthnContextURN);
                }else{
                    //There are no any matched URN for given authnContextClass, so added authnContextClass name to the
                    // AuthnContextClassRef.
                    authnContextClassRef.setAuthnContextClassRef(authnContextClass);
                }

            } else {
                authnContextClassRef.setAuthnContextClassRef(AuthnContext.PPT_AUTHN_CTX);
            }

            /* Authentication Context Comparison Level */
            String authnContextComparison = properties
                    .get(IdentityApplicationConstants.Authenticator.SAML2SSO.AUTHENTICATION_CONTEXT_COMPARISON_LEVEL);

            if (StringUtils.isNotEmpty(authnContextComparison)) {
                if (AuthnContextComparisonTypeEnumeration.EXACT.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
                } else if (AuthnContextComparisonTypeEnumeration.MINIMUM.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);
                } else if (AuthnContextComparisonTypeEnumeration.MAXIMUM.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MAXIMUM);
                } else if (AuthnContextComparisonTypeEnumeration.BETTER.toString().equalsIgnoreCase(
                        authnContextComparison)) {
                    requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.BETTER);
                }
            } else {
                requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.EXACT);
            }
            requestedAuthnContext.getAuthnContextClassRefs().add(authnContextClassRef);
        }
        return requestedAuthnContext;
    }
    
    private boolean isForceAuthenticate(AuthenticationContext context) {
        
        boolean forceAuthenticate = false;
        String forceAuthenticateProp = properties
                .get(IdentityApplicationConstants.Authenticator.SAML2SSO.FORCE_AUTHENTICATION);
        if ("yes".equalsIgnoreCase(forceAuthenticateProp)) {
            forceAuthenticate = true;
        } else if ("as_request".equalsIgnoreCase(forceAuthenticateProp)) {
            forceAuthenticate = context.isForceAuthenticate();
        } 
        return forceAuthenticate;
    }

    private String encodeRequestMessage(RequestAbstractType requestMessage)
            throws SAMLSSOException {

        Marshaller marshaller = Configuration.getMarshallerFactory().getMarshaller(requestMessage);
        Element authDOM = null;
        try {
            authDOM = marshaller.marshall(requestMessage);

            /* Compress the message */
            Deflater deflater = new Deflater(Deflater.DEFLATED, true);
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
            StringWriter rspWrt = new StringWriter();
            XMLHelper.writeNode(authDOM, rspWrt);
            deflaterOutputStream.write(rspWrt.toString().getBytes());
            deflaterOutputStream.close();

            /* Encoding the compressed message */
            String encodedRequestMessage = Base64.encodeBytes(byteArrayOutputStream.toByteArray(), Base64.DONT_BREAK_LINES);

            byteArrayOutputStream.write(byteArrayOutputStream.toByteArray());
            byteArrayOutputStream.toString();

            // log saml
            if (log.isDebugEnabled()) {
                log.debug("SAML Request  :  " + rspWrt.toString());
            }

            return URLEncoder.encode(encodedRequestMessage, "UTF-8").trim();

        } catch (MarshallingException e) {
            throw new SAMLSSOException("Error occurred while encoding SAML request", e);
        } catch (UnsupportedEncodingException e) {
            throw new SAMLSSOException("Error occurred while encoding SAML request", e);
        } catch (IOException e) {
            throw new SAMLSSOException("Error occurred while encoding SAML request", e);
        }
    }

    private XMLObject unmarshall(String samlString) throws SAMLSSOException {

        XMLObject response;
        try {
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setIgnoringComments(true);
            Document document = getDocument(documentBuilderFactory, samlString);
            if (isSignedWithComments(document)) {
                documentBuilderFactory.setIgnoringComments(false);
                document = getDocument(documentBuilderFactory, samlString);
            }
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);
            response = unmarshaller.unmarshall(element);
            // Check for duplicate samlp:Response
            NodeList list = response.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20P_NS, "Response");
            if (list.getLength() > 0) {
                log.error("Invalid schema for the SAML2 response. Multiple Response elements found.");
                throw new SAMLSSOException("Error occurred while processing SAML2 response.");
            }

            // Checking for multiple Assertions
            NodeList assertionList = response.getDOM().getElementsByTagNameNS(SAMLConstants.SAML20_NS, "Assertion");
            if (assertionList.getLength() > 1) {
                log.error("Invalid schema for the SAML2 response. Multiple Assertion elements found.");
                throw new SAMLSSOException("Error occurred while processing SAML2 response.");
            }
            return response;
        } catch (ParserConfigurationException e) {
            throw new SAMLSSOException("Error in unmarshalling SAML Request from the encoded String", e);
        } catch (UnmarshallingException e) {
            throw new SAMLSSOException("Error in unmarshalling SAML Request from the encoded String", e);
        } catch (SAXException e) {
            throw new SAMLSSOException("Error in unmarshalling SAML Request from the encoded String", e);
        } catch (IOException e) {
            throw new SAMLSSOException("Error in unmarshalling SAML Request from the encoded String", e);
        }

    }

    /**
     * Return whether SAML Assertion has the canonicalization method
     * set to 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'.
     *
     * @param document
     * @return true if canonicalization method equals to 'http://www.w3.org/2001/10/xml-exc-c14n#WithComments'
     */
    private static boolean isSignedWithComments(Document document) {

        XPath xPath = XPathFactory.newInstance().newXPath();
        try {
            String assertionId = (String) xPath.compile("//*[local-name()='Assertion']/@ID")
                    .evaluate(document, XPathConstants.STRING);

            if (StringUtils.isBlank(assertionId)) {
                return false;
            }

            NodeList nodeList = ((NodeList) xPath.compile(
                    "//*[local-name()='Assertion']" +
                            "/*[local-name()='Signature']" +
                            "/*[local-name()='SignedInfo']" +
                            "/*[local-name()='Reference'][@URI='#" + assertionId + "']" +
                            "/*[local-name()='Transforms']" +
                            "/*[local-name()='Transform']" +
                            "[@Algorithm='http://www.w3.org/2001/10/xml-exc-c14n#WithComments']")
                    .evaluate(document, XPathConstants.NODESET));
            return nodeList != null && nodeList.getLength() > 0;
        } catch (XPathExpressionException e) {
            String message = "Failed to find the canonicalization algorithm of the assertion. Defaulting to: " +
                    "http://www.w3.org/2001/10/xml-exc-c14n#";
            log.warn(message);
            if (log.isDebugEnabled()) {
                log.debug(message, e);
            }
            return false;
        }
    }

    private static Document getDocument(DocumentBuilderFactory documentBuilderFactory, String samlString)
            throws IOException, SAXException, ParserConfigurationException {

        documentBuilderFactory.setNamespaceAware(true);
        documentBuilderFactory.setExpandEntityReferences(false);
        documentBuilderFactory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        org.apache.xerces.util.SecurityManager securityManager = new SecurityManager();
        securityManager.setEntityExpansionLimit(ENTITY_EXPANSION_LIMIT);
        documentBuilderFactory.setAttribute(SECURITY_MANAGER_PROPERTY, securityManager);

        DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
        docBuilder.setEntityResolver(new CarbonEntityResolver());
        ByteArrayInputStream inputStream = new ByteArrayInputStream(samlString.getBytes());
        return docBuilder.parse(inputStream);
    }

    /*
     * Process the response and returns the results
     */
    private Map<ClaimMapping, String> getAssertionStatements(Assertion assertion) {

        Map<ClaimMapping, String> results = new HashMap<ClaimMapping, String>();

        String multiAttributeSeparator = DEFAULT_MULTI_ATTRIBUTE_SEPARATOR;

        UserRealm realm;
        try {
            realm = SAMLSSOAuthenticatorServiceComponent.getRealmService().getTenantUserRealm
                    (MultitenantConstants.SUPER_TENANT_ID);
            UserStoreManager userStoreManager = (UserStoreManager) realm.getUserStoreManager();

            multiAttributeSeparator = userStoreManager.
                    getRealmConfiguration().getUserStoreProperty(MULTI_ATTRIBUTE_SEPARATOR);
        } catch (UserStoreException e) {
            log.warn("Error while reading MultiAttributeSeparator valaue from primary user store ", e);
        }

        if (assertion != null) {
            List<AttributeStatement> attributeStatementList = assertion.getAttributeStatements();

            if (attributeStatementList != null) {
                for (AttributeStatement statement : attributeStatementList) {
                    List<Attribute> attributesList = statement.getAttributes();
                    for (Attribute attribute : attributesList) {
                        List<XMLObject> values = attribute.getAttributeValues();
                        String attributesValue = null;
                        if (values != null) {
                            for (int i = 0; i < values.size(); i++) {
                                Element value = attribute.getAttributeValues().get(i).getDOM();
                                String attributeValue = value.getTextContent();
                                if (StringUtils.isBlank(attributesValue)) {
                                    attributesValue = attributeValue;
                                } else {
                                    attributesValue = attributesValue + multiAttributeSeparator + attributeValue;
                                }
                            }
                        }

                        results.put(ClaimMapping.build(attribute.getName(),
                                attribute.getName(), null, false), attributesValue);
                    }
                }
            }
        }
        return results;
    }

    /**
     * Validate the AudienceRestriction of SAML2 Response
     *
     * @param assertion SAML2 Assertion
     * @return validity
     */
    private void validateAudienceRestriction(Assertion assertion) throws SAMLSSOException {

        if (assertion != null) {
            Conditions conditions = assertion.getConditions();
            if (conditions != null) {
                List<AudienceRestriction> audienceRestrictions = conditions.getAudienceRestrictions();
                if (audienceRestrictions != null && !audienceRestrictions.isEmpty()) {
                    for (AudienceRestriction audienceRestriction : audienceRestrictions) {
                        if (CollectionUtils.isNotEmpty(audienceRestriction.getAudiences())) {
                            boolean audienceFound = false;
                            for (Audience audience : audienceRestriction.getAudiences()) {
                                if (properties.get(IdentityApplicationConstants.Authenticator.SAML2SSO.SP_ENTITY_ID)
                                        .equals(audience.getAudienceURI())) {
                                    audienceFound = true;
                                    break;
                                }
                            }
                            if (!audienceFound) {
                                throw new SAMLSSOException("SAML Assertion Audience Restriction validation failed");
                            }
                        } else {
                            throw new SAMLSSOException("SAML Response's AudienceRestriction doesn't contain Audiences");
                        }
                    }
                } else {
                    throw new SAMLSSOException("SAML Response doesn't contain AudienceRestrictions");
                }
            } else {
                throw new SAMLSSOException("SAML Response doesn't contain Conditions");
            }
        }
    }


    /**
     * Validate the signature of a SAML2 Response and Assertion
     *
     * @param response SAML2 Response
     * @return true, if signature is valid.
     */
    private void validateSignature(Response response, Assertion assertion) throws
            SAMLSSOException {

        if (SSOUtils.isAuthnResponseSigned(properties)) {

            XMLObject signature = response.getSignature();
            if (signature == null) {
                throw new SAMLSSOException("SAMLResponse signing is enabled, but signature element " +
                        "not found in SAML Response element.");
            } else {
                validateSignature(signature);
            }
        }
        if (SSOUtils.isAssertionSigningEnabled(properties)) {

            XMLObject signature = assertion.getSignature();
            if (signature == null) {
                throw new SAMLSSOException("SAMLAssertion signing is enabled, but signature element " +
                        "not found in SAML Assertion element.");
            } else {
                validateSignature(signature);
            }
        }
    }

    /**
     * Validates the XML Signature object
     *
     * @param signature XMLObject
     * @throws SAMLSSOException
     */
    private void validateSignature(XMLObject signature) throws SAMLSSOException {
        SignatureImpl signImpl = (SignatureImpl) signature;
        try {
            SAMLSignatureProfileValidator signatureProfileValidator = new SAMLSignatureProfileValidator();
            signatureProfileValidator.validate(signImpl);

            // Following code segment is taken from org.opensaml.security.SAMLSignatureProfileValidator
            // of OpenSAML 2.6.4. This is done to get the latest XSW related fixes.
            XMLSignature apacheSig = signImpl.getXMLSignature();
            SignableSAMLObject signableObject = (SignableSAMLObject) signature.getParent();

            Reference ref = null;
            try {
                ref = apacheSig.getSignedInfo().item(0);
            } catch (XMLSecurityException e) {
                // This exception should never occur, because it's already checked
                // from the previous call to signatureProfileValidator#validate
                log.error("Apache XML Security exception obtaining Reference", e);
                throw new ValidationException("Could not obtain Reference from Signature/SignedInfo", e);
            }

            String uri = ref.getURI();

            validateReferenceURI(uri, signableObject);
            validateObjectChildren(apacheSig);

            // End of OpenSAML 2.6.4 logic
            // -----------------------------------------------------------------------------

        } catch (ValidationException ex) {
            String logMsg = "Signature do not confirm to SAML signature profile. Possible XML Signature " +
                    "Wrapping  Attack!";
            AUDIT_LOG.warn(logMsg);
            if (log.isDebugEnabled()) {
                log.debug(logMsg, ex);
            }
            throw new SAMLSSOException(logMsg, ex);
        }

        if (identityProvider.getCertificate() == null || identityProvider.getCertificate().isEmpty()) {
            throw new SAMLSSOException("Signature validation is enabled, but IdP doesn't have a certificate");
        }

        try{
            X509Credential credential = new X509CredentialImpl(tenantDomain, identityProvider.getCertificate());
            SignatureValidator validator = new SignatureValidator(credential);
            validator.validate(signImpl);
        } catch (ValidationException e) {
            throw new SAMLSSOException("Signature validation failed for SAML Response", e);
        }
    }

    /**
     * Validates the 'Not Before' and 'Not On Or After' conditions of the SAML Assertion
     *
     * @param assertion SAML Assertion element
     * @throws SAMLSSOException
     */
    private void validateAssertionValidityPeriod(Assertion assertion) throws SAMLSSOException{

        if (isVerifyAssertionValidityPeriod()) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Assertion validity period verification is enabled. Verifying 'Not Before' and " +
                        "'Not On Or After' conditions.");
            }
            DateTime validFrom = assertion.getConditions().getNotBefore();
            DateTime validTill = assertion.getConditions().getNotOnOrAfter();
            int timeStampSkewInSeconds = getTimeStampSkewInSeconds();

            if (validFrom != null && validFrom.minusSeconds(timeStampSkewInSeconds).isAfterNow()) {
                throw new SAMLSSOException("Failed to meet SAML Assertion Condition 'Not Before'");
            }

            if (validTill != null && validTill.plusSeconds(timeStampSkewInSeconds).isBeforeNow()) {
                throw new SAMLSSOException("Failed to meet SAML Assertion Condition 'Not On Or After'");
            }

            if (validFrom != null && validTill != null && validFrom.isAfter(validTill)) {
                throw new SAMLSSOException(
                        "SAML Assertion Condition 'Not Before' must be less than the value of 'Not On Or After'");
            }
        }
    }

    /**
     * Validate the Signature's Reference URI.
     *
     * First validate the Reference URI against the parent's ID itself.  Then validate that the
     * URI (if non-empty) resolves to the same Element node as is cached by the SignableSAMLObject.
     *
     *
     * @param uri the Signature Reference URI attribute value
     * @param signableObject the SignableSAMLObject whose signature is being validated
     * @throws ValidationException  if the URI is invalid or doesn't resolve to the expected DOM node
     */
    private void validateReferenceURI(String uri, SignableSAMLObject signableObject) throws ValidationException {
        if (DatatypeHelper.isEmpty(uri)) {
            return;
        }

        String uriID = uri.substring(1);

        Element expected = signableObject.getDOM();
        if (expected == null) {
            log.error("SignableSAMLObject does not have a cached DOM Element.");
            throw new ValidationException("SignableSAMLObject does not have a cached DOM Element.");
        }
        Document doc = expected.getOwnerDocument();

        Element resolved = IdResolver.getElementById(doc, uriID);
        if (resolved == null) {
            log.error("Apache xmlsec IdResolver could not resolve the Element for id reference: " + uriID);
            throw new ValidationException("Apache xmlsec IdResolver could not resolve the Element for id reference: "
                    +  uriID);
        }

        if (!expected.isSameNode(resolved)) {
            log.error("Signature Reference URI " + uri + " did not resolve to the expected parent Element");
            throw new ValidationException("Signature Reference URI did not resolve to the expected parent Element");
        }
    }

    /**
     * Validate that the Signature instance does not contain any ds:Object children.
     *
     * @param apacheSig the Apache XML Signature instance
     * @throws ValidationException if the signature contains ds:Object children
     */
    private void validateObjectChildren(XMLSignature apacheSig) throws ValidationException {
        if (apacheSig.getObjectLength() > 0) {
            log.error("Signature contained " + apacheSig.getObjectLength() + " ds:Object child element(s)");
            throw new ValidationException("Signature contained illegal ds:Object children");
        }
    }

    /**
     * Get Decrypted Assertion
     *
     * @param encryptedAssertion
     * @return
     * @throws Exception
     */
    private Assertion getDecryptedAssertion(EncryptedAssertion encryptedAssertion) throws Exception {

        X509Credential credential = new X509CredentialImpl(tenantDomain, null);
        KeyInfoCredentialResolver keyResolver = new StaticKeyInfoCredentialResolver(credential);
        EncryptedKey key = encryptedAssertion.getEncryptedData().getKeyInfo().getEncryptedKeys().get(0);
        Decrypter decrypter = new Decrypter(null, keyResolver, null);
        SecretKey dkey = (SecretKey) decrypter.decryptKey(key, encryptedAssertion.getEncryptedData().
                getEncryptionMethod().getAlgorithm());
        Credential shared = SecurityHelper.getSimpleCredential(dkey);
        decrypter = new Decrypter(new StaticKeyInfoCredentialResolver(shared), null, null);
        decrypter.setRootInNewDocument(true);
        return decrypter.decrypt(encryptedAssertion);
    }

    /**
     * Check whether the Assertion validity period validation is enabled or disabled in the
     * application-authentication.xml configuration file.
     *
     * @return true only if SAMLSSOAuthenticator configuration has the configuration
     * <Parameter name="VerifyAssertionValidityPeriod">true</Parameter>
     * Otherwise returns false
     */
    private boolean isVerifyAssertionValidityPeriod() {

        AuthenticatorConfig authenticatorConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap().get(
                        SSOConstants.AUTHENTICATOR_NAME);
        if (authenticatorConfig != null) {
            String verifyAssertionValidityPeriod =
                    authenticatorConfig.getParameterMap().get(VERIFY_ASSERTION_VALIDITY_PERIOD);
            if (StringUtils.isNotBlank(verifyAssertionValidityPeriod)) {
                return Boolean.parseBoolean(verifyAssertionValidityPeriod);
            }
        }

        return false;
    }

    /**
     * Returns the assertion validity time stamp skew configured in application-authentication.xml configuration file.
     *
     * @return the value configured under the SAMLSSOAuthenticator configuration with below parameter
     * <Parameter name="TimestampSkew">300</Parameter>
     * If the configuration is not available returns 300 s by default
     */
    private int getTimeStampSkewInSeconds() {

        AuthenticatorConfig authenticatorConfig =
                FileBasedConfigurationBuilder.getInstance().getAuthenticatorConfigMap().get(
                        SSOConstants.AUTHENTICATOR_NAME);
        if (authenticatorConfig != null) {
            String timeStampSkew = authenticatorConfig.getParameterMap().get(TIME_STAMP_SKEW);
            if (timeStampSkew != null) {
                timeStampSkewInSeconds = Integer.parseInt(timeStampSkew);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("TimestampSkew is set to " + timeStampSkewInSeconds + " s.");
        }

        return timeStampSkewInSeconds;
    }
}
