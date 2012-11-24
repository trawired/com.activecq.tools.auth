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
package com.activecq.tools.auth;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.sling.auth.core.spi.AuthenticationInfo;

public interface SessionAuthenticationService extends PluggableAuthenticationHandler {

    /**
     * Custom implementation for Removing the Session-based authentication credentials from the Request/Response.
     *
     * Example. Expire authentication Cookie, and adds it to the Response
     *
     * @param request
     * @param response
     * @param cookieName
     * @return
     */
    public boolean dropCredentials(HttpServletRequest request, HttpServletResponse response);

    /**
     * Custom implementation for Adding Session-based authentication credentials to the Request/Response.
     *
     * Example. Create and add a authentication Cookie to the Request, using the AuthenticationInfo object as the source user data
     *
     * @param request
     * @param response
     * @param authInfo
     * @return
     */
    public boolean addCredentials(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo);
}