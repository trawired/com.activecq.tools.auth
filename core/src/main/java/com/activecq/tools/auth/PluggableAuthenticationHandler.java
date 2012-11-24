/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.activecq.tools.auth;

import javax.jcr.Credentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.sling.auth.core.spi.AuthenticationInfo;

/**
 *
 * @author david
 */
public interface PluggableAuthenticationHandler {
    /**
     * Determines whether this Authentication Service meets the criteria to authenticate this request
     *
     * @param request
     * @return
     */
    public boolean accepts(HttpServletRequest request);

    /**
     * Get the Session-based authentication credentials from the Request.
     *
     * Example. Gets an authentication Cookie from the Request, validates the cookie data, derives the CQ Username, and creates the Simple Credentials object from the CQ Username.
     *
     * @param request
     * @param cookieName
     * @param secret
     * @return userId of validated cookie user or null
     */
    public Credentials extractCredentials(HttpServletRequest request);

    /**
     * Returns true or false, instructing the PluggableAuthenticationHandler to use the implemented authenticationFailed(..)
     * @return
     */
    public boolean useAuthenticationFailed();

    /**
     * Custom implementation for authenticationFailed, which is called after authentication fails
     *
     * @param request
     * @param response
     * @param authInfo
     * @return
     */
    public void authenticationFailed(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo);

    /**
     * Returns true or false, instructing the PluggableAuthenticationHandler to use the implemented authenticationSuceeded(..)
     * @return
     */
    public boolean useAuthenticationSucceeded();

    /**
     * Custom implementation for authenticationSucceeded, which is called after authentication succeeds
     *
     * @param request
     * @param response
     * @param authInfo
     * @return
     */
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo);

}
