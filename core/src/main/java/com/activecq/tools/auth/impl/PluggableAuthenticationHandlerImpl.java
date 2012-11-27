/*
 * Copyright 2012 david gonzalez.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.activecq.tools.auth.impl;

import com.activecq.api.utils.HttpRequestUtil;
import com.activecq.api.utils.TextUtil;
import com.activecq.tools.auth.CredentialsAuthenticationService;
import com.activecq.tools.auth.SessionAuthenticationService;
import com.day.cq.commons.PathInfo;
import java.io.IOException;
import java.util.Dictionary;
import java.util.logging.Level;
import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.apache.felix.scr.annotations.*;
import org.apache.sling.api.auth.Authenticator;
import org.apache.sling.api.resource.LoginException;
import org.apache.sling.api.resource.ResourceResolver;
import org.apache.sling.api.resource.ResourceResolverFactory;
import org.apache.sling.auth.core.AuthenticationSupport;
import org.apache.sling.auth.core.spi.AuthenticationFeedbackHandler;
import org.apache.sling.auth.core.spi.AuthenticationHandler;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.apache.sling.jcr.resource.JcrResourceConstants;
import org.osgi.service.component.ComponentContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

// Deprecated: org.apache.sling.engine.auth

@Component(label="ActiveCQ - Pluggable Authentication Handler",
        description="This service provides an extensible framework for Form and Session authentication.",
        metatype=true,
        immediate=true,
        configurationFactory=true)

@Properties ({
    @Property(label="Friendly Name",
            description="Friendly name for this Authentication Handler configuration",
            name="service.description",
            value="ActiveCQ Pluggable Authentication Handler",
            propertyPrivate=false),

    @Property(label="Enable",
            description="Enable/disable this authentication handler",
            name="prop.enabled",
            boolValue=false,
            propertyPrivate=false),

    @Property(label="Authentication Paths",
            description="JCR Paths which this Authentication Handler will authenticate. [Default: /]",
            name=AuthenticationHandler.PATH_PROPERTY,
            value={"/"},
            cardinality=Integer.MAX_VALUE),

    @Property(label = "Service Ranking",
            description="Service ranking. Higher gives more priority.",
            name = "service.ranking",
            intValue = 20,
            propertyPrivate = false),

    @Property(
            label="Session Authentication Service ID",
            description="Filter expression for selecting the implemenation of the SessionAuthenticationService. Example: (service.id=default)",
            name="sessionAuthenticationService.target",
            value="(service.uid=default)"),

     @Property(
            label="Form Authentication Service ID",
            description="Filter expression for selecting the implemenation of the FormAuthenticationService. Example: (service.id=default)",
            name="formAuthenticationService.target",
            value="(service.uid=default)"),

    @Property(
            name = AuthenticationHandler.TYPE_PROPERTY,
            value = HttpServletRequest.FORM_AUTH,
            propertyPrivate = true),

    @Property(label = "Vendor",
            name = "service.vendor",
            value = "ActiveCQ",
            propertyPrivate = true)
})

@Service
public class PluggableAuthenticationHandlerImpl implements AuthenticationHandler, AuthenticationFeedbackHandler  {
    public enum AuthType {
        FORM,
        SESSION
    }

    public static final String HTTP_REQUEST_REFERER = "referer";
    public static final String HTTP_REQUEST_ATTR_AUTH_TYPE = "__activecq_auth_type_";

    @Reference(target="(service.uid=default)")
    SessionAuthenticationService sessionAuthenticationService;

    @Reference(target="(service.uid=default)")
    CredentialsAuthenticationService formAuthenticationService;

    @SuppressWarnings("unused")
    private final Logger log = LoggerFactory.getLogger(this.getClass().getName());

    private static final boolean DEFAULT_ENABLED = false;
    private String PROP_ENABLED = "prop.enabled";
    private boolean enabled = DEFAULT_ENABLED;

    private static final String DEFAULT_TRUST_CREDENTIALS = "TrustedInfo";
    private String trustCredentials = DEFAULT_TRUST_CREDENTIALS;
    @Property(label="Trust Credentials",
        description="The CQ Trust Credentials found in repository.xml or ldap.config",
        value=DEFAULT_TRUST_CREDENTIALS)
    private static final String PROP_TRUST_CREDENTIALS = "prop.trust-credentials";

    private static final String DEFAULT_REQUEST_CREDENTIALS_REDIRECT = "/sign-in.html";
    private String requestCredentialsRedirect = DEFAULT_REQUEST_CREDENTIALS_REDIRECT;
    @Property(label="Request Credentials Redirect URI",
        description="requestCredentials(..) will redirect to this page when the appropriate conditions are met. Leave blank to return false;",
        value=DEFAULT_REQUEST_CREDENTIALS_REDIRECT)
    private static final String PROP_REQUEST_CREDENTIALS_REDIRECT = "prop.request-credentials.redirect";

    @Reference
    private ResourceResolverFactory resourceResolverFactory;

    private ResourceResolver adminResourceResolver;

    /**
     * Extract the credentials contained inside the request, parameter or cookie
     *
     * @see com.day.cq.auth.impl.AbstractHTTPAuthHandler#authenticate(javax.servlet.http.HttpServletRequest,
     *      javax.servlet.http.HttpServletResponse)
     */
    @Override
    public AuthenticationInfo extractCredentials(HttpServletRequest request,
            HttpServletResponse response) {
        if(!this.enabled) { return null; }

        Credentials credentials;
        boolean useTrustCredentials = false;

        if(formAuthenticationService.accepts(request)) {
            credentials = formAuthenticationService.extractCredentials(request);
            request.setAttribute(HTTP_REQUEST_ATTR_AUTH_TYPE, AuthType.FORM);
        } else if(sessionAuthenticationService.accepts(request)) {
            credentials = sessionAuthenticationService.extractCredentials(request);
            request.setAttribute(HTTP_REQUEST_ATTR_AUTH_TYPE, AuthType.SESSION);
            useTrustCredentials = true;
        } else {
            return null;
        }

        if (credentials == null) {
            /* Remove invalid cookies to cut down on future processing.
             * This is executed for all failed attempts. If an authenticated
             * user tries to unsuccessfully login they will be logged out.
             */
            // TODO Think on this; determine if this is the right course of action
            sessionAuthenticationService.dropCredentials(request, response);
            return null;
        }

        // Handle SimpleCredentials (Default CQ behavior, vs Custom Credentials)
        AuthenticationInfo info;

        if(credentials instanceof SimpleCredentials) {
            // Handle common case of using SimpleCredentials
            // This case is supported by the OOTB Adobe CQ CRXLoginModule

            SimpleCredentials simpleCredentials = (SimpleCredentials) credentials;

            if(useTrustCredentials) {
                // Set Trusted Credentials Attributes; Must match to what is in
                // repository.xml or ldap.config (if LDAP is used)
                simpleCredentials.setAttribute(trustCredentials, "ignore");
            }

            info = new AuthenticationInfo(HttpServletRequest.FORM_AUTH, simpleCredentials.getUserID());

            // Set AuthenticationInfo Password if available
            if(simpleCredentials.getPassword() != null && simpleCredentials.getPassword().length > 0) {
                info.setPassword(simpleCredentials.getPassword());
            }
        } else {
            // Handle the case where Authentication should be preformed against a
            // custom LoginModulePlugin (http://sling.apache.org/apidocs/sling6/org/apache/sling/jcr/jackrabbit/server/security/LoginModulePlugin.html)
            info = new AuthenticationInfo(HttpServletRequest.FORM_AUTH);
        }

        // Add the Credentials object to the AuthenticationInfo for processing by
        // the LoginModule/LoginModulePlugin
        info.put(JcrResourceConstants.AUTHENTICATION_INFO_CREDENTIALS, credentials);

        return info;
    }

    @Override
    public void dropCredentials(HttpServletRequest request,
            HttpServletResponse response) {
        if(!this.enabled) { return; }

        sessionAuthenticationService.dropCredentials(request, response);
    }

    @Override
    public boolean requestCredentials(HttpServletRequest request,
            HttpServletResponse response) {
        if(!this.enabled) { return false; }

        if(StringUtils.isBlank(requestCredentialsRedirect) ||
                StringUtils.equals(requestCredentialsRedirect, "null")) {
            return false;
        } else {
            try {
                response.sendRedirect(requestCredentialsRedirect);
                return true;
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(PluggableAuthenticationHandlerImpl.class.getName()).log(Level.SEVERE, null, ex);
                return false;
            }
        }
    }

    @Override
    public void authenticationFailed(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
        final AuthType authType = (AuthType) request.getAttribute(HTTP_REQUEST_ATTR_AUTH_TYPE);

        if(AuthType.FORM.equals(authType) && formAuthenticationService.useAuthenticationSucceeded()) {
            formAuthenticationService.authenticationFailed(request, response, authInfo);
        } else if(AuthType.SESSION.equals(authType) && sessionAuthenticationService.useAuthenticationSucceeded()) {
            sessionAuthenticationService.authenticationFailed(request, response, authInfo);
        } else {
            // Standard Authentication Failed Redirect
            final String redirect = TextUtil.getFirstNonEmpty(
                    requestCredentialsRedirect,
                    request.getRequestURL().toString(),
                    request.getHeader(HTTP_REQUEST_REFERER));

            if(redirect == null) { return; }
            // Dont allow redirect back to the resource that spawned the authentication request
            if(isCircularRedirect(request, redirect)) { return; }

            try {
                response.sendRedirect(redirect);
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(PluggableAuthenticationHandlerImpl.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
        final AuthType authType = (AuthType) request.getAttribute(HTTP_REQUEST_ATTR_AUTH_TYPE);

        if(AuthType.FORM.equals(authType) && formAuthenticationService.useAuthenticationSucceeded()) {
            return formAuthenticationService.authenticationSucceeded(request, response, authInfo);
        } else if(AuthType.SESSION.equals(authType) && sessionAuthenticationService.useAuthenticationSucceeded()) {
            return sessionAuthenticationService.authenticationSucceeded(request, response, authInfo);
        } else {
            // Standard Authentication Succeed Flow
            sessionAuthenticationService.addCredentials(request, response, authInfo);

            final String redirectPath = getRedirectResource(request);

            if(redirectPath == null) { return false; }

            try {
                response.sendRedirect(redirectPath);
            } catch (IOException ex) {
                java.util.logging.Logger.getLogger(PluggableAuthenticationHandlerImpl.class.getName()).log(Level.SEVERE, null, ex);
                return false;
            }
            return true;
        }
    }

    /** OSGi Activate/Deactivate **/

    protected void activate(ComponentContext componentContext) {
        Dictionary properties = componentContext.getProperties();

        enabled = PropertiesUtil.toBoolean(properties.get(PROP_ENABLED), DEFAULT_ENABLED);

        trustCredentials = PropertiesUtil.toString(
                properties.get(PROP_TRUST_CREDENTIALS), DEFAULT_TRUST_CREDENTIALS);

        requestCredentialsRedirect = StringUtils.stripToEmpty(PropertiesUtil.toString(
                properties.get(PROP_REQUEST_CREDENTIALS_REDIRECT), DEFAULT_REQUEST_CREDENTIALS_REDIRECT));

        try {
            adminResourceResolver = resourceResolverFactory.getAdministrativeResourceResolver(null);
        } catch(LoginException ex) { }
    }

    protected void deactivate(ComponentContext componentContext) {
        sessionAuthenticationService = null;
        formAuthenticationService = null;

        this.enabled = DEFAULT_ENABLED;

        if(adminResourceResolver != null) {
            adminResourceResolver.close();
            adminResourceResolver = null;
        }
    }

    /** Private Methods **/

    /**
     * Gets the resource to (optionally) redirect to on success.
     *
     * @param request
     * @return
     */
    private String getRedirectResource(HttpServletRequest request) {
        String redirect = TextUtil.getFirstNonEmpty(
                HttpRequestUtil.getParameterOrAttribute(request, Authenticator.LOGIN_RESOURCE), // "resource"
                HttpRequestUtil.getParameterOrAttribute(request, AuthenticationSupport.REDIRECT_PARAMETER)); // "sling.auth.redirect"

        if(StringUtils.isBlank(redirect)) { return null; }

        PathInfo pathInfo;

        try {
            pathInfo = new PathInfo(redirect);
        } catch (IllegalArgumentException ex) {
            return null;
        }

        if(pathInfo == null) { return redirect; }

        if(StringUtils.isBlank(pathInfo.getExtension())) {
            redirect = HttpRequestUtil.toString(pathInfo);
        }

        if(adminResourceResolver != null && redirect != null) {
            final String mappedRedirect = adminResourceResolver.map(redirect);
            if(StringUtils.isNotBlank(mappedRedirect)) {
                redirect = mappedRedirect;
            }
        }

        return redirect;
    }

    private boolean isCircularRedirect(HttpServletRequest request, String current) {
        return StringUtils.equals(request.getRequestURI(), current);
    }
}