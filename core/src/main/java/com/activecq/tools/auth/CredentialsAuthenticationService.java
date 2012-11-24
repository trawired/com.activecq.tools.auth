/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.activecq.tools.auth;

import java.util.Map;
import javax.jcr.SimpleCredentials;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.sling.auth.core.spi.AuthenticationInfo;

/**
 *
 * @author david
 */
public interface CredentialsAuthenticationService extends PluggableAuthenticationHandler {

    /**
     * Get reasons for why authentication failed.
     *
     * @param request
     * @return
     */
    public Map<String, String> getReasons(HttpServletRequest request);
}
