/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.activecq.tools.auth.impl;

import com.activecq.api.utils.HttpRequestUtil;
import com.activecq.tools.auth.CredentialsAuthenticationService;
import com.day.cq.commons.PathInfo;
import java.util.Dictionary;
import java.util.HashMap;
import java.util.Map;
import javax.jcr.Credentials;
import javax.jcr.SimpleCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.felix.scr.annotations.Component;
import org.apache.felix.scr.annotations.Properties;
import org.apache.felix.scr.annotations.Property;
import org.apache.felix.scr.annotations.Service;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.osgi.service.component.ComponentContext;


@Component(label = "ActiveCQ - Form Credentials Authentication",
        configurationFactory = true,
        immediate = true,
        metatype = true)

@Properties( {
    @Property(label = "Service Unique ID",
            description = "Must be unique between other Configurations. Must be the same between all servers",
            name = "service.uid",
            value = "default",
            propertyPrivate = false),

    @Property(label = "Service Ranking",
            description="Service ranking. Higher gives more priority.",
            name = "service.ranking",
            intValue = 20,
            propertyPrivate = false),

    @Property(label = "Vendor",
            name = "service.vendor",
            value = "ActiveCQ",
            propertyPrivate = true)
})

@Service
public class FormAuthenticationImpl implements CredentialsAuthenticationService{
    private static final String SUFFIX_J_SECURITY_CHECK = "j_security_check";
    private static final String USERNAME = "j_username";
    private static final String PASSWORD = "j_password";

    /**
     * Sling Property - Suffixes
     */
    private String[] suffixes = DEFAULT_SUFFIXES;
    private static final String[] DEFAULT_SUFFIXES = { SUFFIX_J_SECURITY_CHECK };
    @Property(label="URI Suffix",
            description="URI Suffixes to process as Credential Authentication requests",
            value={ SUFFIX_J_SECURITY_CHECK },
            cardinality=100)
    private static final String PROP_SUFFIXES = "prop.suffixes";

    @Override
    public boolean accepts(HttpServletRequest request) {
        if(request == null) { return false; }
        PathInfo pathInfo = new PathInfo(request.getPathInfo());
        if(suffixes == null || pathInfo == null) { return false; }
        if(suffixes.length < 1) { return false; }
        if(StringUtils.isBlank(pathInfo.getSuffix())) { return false; }

        final String suffix = StringUtils.removeStart(pathInfo.getSuffix(), "/");
        return ArrayUtils.contains(suffixes, suffix);
    }

    @Override
    public Credentials extractCredentials(HttpServletRequest request) {
        if(request == null) { return null; }

        final String username = HttpRequestUtil.getAttributeOrParameter(request, USERNAME, "");
        final String password = HttpRequestUtil.getAttributeOrParameter(request, PASSWORD, "");

        if(password == null) {
            return new SimpleCredentials(username, new char[0]);
        } else {
            return new SimpleCredentials(username, password.toCharArray());
        }
    }

    @Override
    public boolean useAuthenticationFailed() {
        return false;
    }

    @Override
    public void authenticationFailed(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
        // Do nothing; useAuthenticationFailed() returns false.
        throw new UnsupportedOperationException("FormAuthenticationImpl.useAuthenticationFailed() returns false.");
    }

    @Override
    public boolean useAuthenticationSucceeded() {
        return false;
    }

    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
        // Return false; useAuthenticationSucceeded() returns false, so this should never be called.
        // If this is called, then there is a problem.
        throw new UnsupportedOperationException("FormAuthenticationImpl.useAuthenticationSucceeded() returns false.");
    }

    @Override
    public Map<String, String> getReasons(HttpServletRequest request) {
        Map<String, String> reasons = new HashMap<String, String>();
        final String username = HttpRequestUtil.getAttributeOrParameter(request, USERNAME, "");
        final String password = HttpRequestUtil.getAttributeOrParameter(request, PASSWORD, "");

        if(StringUtils.isBlank(username)) {
            reasons.put(USERNAME, "User name is required.");
        } else if(StringUtils.startsWith(username, " ") || StringUtils.endsWith(username, " ")) {
            reasons.put(USERNAME, "User name cannot begin or end with spaces.");
        }

        if(StringUtils.isBlank(password)) {
            reasons.put(PASSWORD, "Password is required.");
        } else if(StringUtils.startsWith(password, " ") || StringUtils.endsWith(username, " ")) {
            reasons.put(PASSWORD, "Password cannot begin or end with spaces.");
        }

        return reasons;
    }

    @SuppressWarnings("unchecked")
    protected void activate(ComponentContext componentContext) {
        Dictionary properties = componentContext.getProperties();
        suffixes = PropertiesUtil.toStringArray(properties.get(PROP_SUFFIXES), DEFAULT_SUFFIXES);
    }

    protected void deactivate(ComponentContext componentContext) {
    }
}
