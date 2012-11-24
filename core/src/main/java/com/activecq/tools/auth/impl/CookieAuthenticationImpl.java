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

import com.activecq.api.utils.CookieUtil;
import com.activecq.api.utils.OsgiPropertyUtil;
import com.activecq.tools.auth.SessionAuthenticationService;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.AbstractMap;
import java.util.Date;
import java.util.Dictionary;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.jcr.SimpleCredentials;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.felix.scr.annotations.*;
import org.apache.sling.auth.core.spi.AuthenticationInfo;
import org.apache.sling.commons.osgi.PropertiesUtil;
import org.osgi.service.component.ComponentContext;

@Component(label = "ActiveCQ - HTTP Cookie Authenticator",
        configurationFactory=true,
        immediate = true,
        metatype = true)

@Properties( {
    @Property(label="Service Unique ID",
            description="Must be unique between other Configurations. Must be the same between all servers",
            name="service.uid",
            value="default"),

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
public class CookieAuthenticationImpl implements SessionAuthenticationService {

    private static final String DATA_DELIMITER = "@";

    /**
     * Sling Property - Cookie Name
     */
    private String cookieName = DEFAULT_COOKIE_NAME;
    private static final String DEFAULT_COOKIE_NAME = "auth";
    @Property(label="Cookie Name",
            description="Must be the same between all servers",
            value=DEFAULT_COOKIE_NAME)
    private static final String PROP_COOKIE_NAME = "prop.token.name";

    /**
     * Sling Property - Cookie Secret
     */
    private static final String DEFAULT_COOKIE_SECRET = "CHANGE_ME_BUT_KEEP_ME_THE_SAME_BETWEEN_SERVERS";
    private String secret = DEFAULT_COOKIE_SECRET;
    @Property(label="Cookie Secret",
            description="Must be the same between all servers. A UUID is a good secret. Changing this value will invalidate previously issued Auth Cookies.",
            value=DEFAULT_COOKIE_SECRET)
    private static final String PROP_COOKIE_SECRET = "prop.token.secret";

    /**
     * Sling Property - Cookie Life
     */
    private static final int DEFAULT_COOKIE_EXPIRY = -1; // Session cookie
    private int cookieExpiry = DEFAULT_COOKIE_EXPIRY;
    @Property(label="Default Cookie Life",
            description="Default cookie expiry in seconds, used if 'Remember Me' expirty isn't set. Defaults to -1 to indicate a Session cookie.",
            intValue=DEFAULT_COOKIE_EXPIRY)
    private static final String PROP_COOKIE_EXPIRY = "prop.session.expiry";


    private static final String DEFAULT_REMEMBER_ME = "remember-me:on";
    private AbstractMap.SimpleEntry rememberMe = new AbstractMap.SimpleEntry(null, null);
    @Property(label="Remember Me",
            description="Request Parameter key:value pair to watch for.",
            value=DEFAULT_REMEMBER_ME)
    private static String PROP_REMEMBER_ME = "prop.session.remember-me";

    /**
     * Sling Property - Remember Me Cookie Life
     */
    private static final long DEFAULT_REMEMBER_ME_COOKIE_EXPIRY = 30; // 30 days
    private int cookieRememberMeExpiry = new Long(DEFAULT_REMEMBER_ME_COOKIE_EXPIRY).intValue();
    @Property(label="Remember Me Cookie Life",
            description="Cookie expiry in days",
            longValue=DEFAULT_COOKIE_EXPIRY)
    private static final String PROP_COOKIE_REMEMBER_ME_EXPIRY = "prop.session.remember-me.expiry";


    /**
     * Sling Property - Hash Algorithm
     *
     * http://docs.oracle.com/javase/6/docs/technotes/guides/security/StandardNames.html
     */
    private static final String DEFAULT_ENCRYPTION_TYPE = "HmacSHA1";
    private static String encryptionType = DEFAULT_ENCRYPTION_TYPE;
    @Property(label="Encryption Algorithm",
            description="Encryption algorithm used to hash secure cookie. Must be the same between all servers",
            value=DEFAULT_ENCRYPTION_TYPE,
            options={@PropertyOption(name="HMAC-SHA1", value="HmacSHA1"),
                    @PropertyOption(name="HMAC-MD5", value="HmacMD5")})
    private static final String PROP_ENCRYPTION_TYPE = "prop.encryption.algorithm";

    /**
     * Sling Property - Cookie Path
     */
    private static final String DEFAULT_COOKIE_PATH = "/";
    private String cookiePath = DEFAULT_COOKIE_PATH;
    @Property(label="Cookie Path",
            description="Cookie Path",
            value=DEFAULT_COOKIE_PATH)
    private static String PROP_COOKIE_PATH = "prop.cookie.path";

    /**
     * Sling Property - Drop Cookies Regexes
     */
    private static final String[] DEFAULT_DROP_COOKIES = new String[] {};
    private String[] dropCookieRegexes = DEFAULT_DROP_COOKIES;
    @Property(label="Drop Cookies",
            description="Drop Cookies",
            cardinality=100000)
    private static String PROP_DROP_COOKIES = "prop.cookie.drop-regexes";

     /**
     * Sling Property - Cookie Encoding
     */
    private static final String DEFAULT_COOKIE_ENCODING = "UTF-8";
    private String cookieEncoding = DEFAULT_COOKIE_ENCODING;
    @Property(label="Cookie Encoding",
            description="Cookie character encoding (Default: UTF-8)",
            value=DEFAULT_COOKIE_ENCODING)
    private static String PROP_COOKIE_ENCODING = "prop.cookie.encoding";

    /**
     * Determines whether this authentication service should authenticate the request
     *
     * @param request
     * @return
     */
    @Override
    public boolean accepts(HttpServletRequest request) {
       return(CookieUtil.getCookie(request, cookieName) != null);
    }

    /**
     * Validate the Authentication Cookie
     *
     * @param request
     * @param cookieName
     * @param secret
     * @return
     */
    @Override
    public SimpleCredentials extractCredentials(HttpServletRequest request) {
        Cookie cookie = CookieUtil.getCookie(request, cookieName);

        if (cookie == null) {
            return null;
        }

        // Get and decode cookie data
        String cookieData;
        try {
            if(StringUtils.isBlank(cookie.getValue())) { return null; }
            final String tmp = new Base64(true).decode(cookie.getValue()).toString();
            cookieData = URLDecoder.decode(tmp, cookieEncoding);
        } catch (UnsupportedEncodingException e) {
            return null;
        }

        // Split the cookie data by the DATA_DELIMITER
        String[] values = splitCookieData(cookieData);

        if (values == null) {
            return null;
        }

        final String token = StringUtils.trimToNull(values[0]);
        final String timestamp = StringUtils.trimToNull(values[1]);
        final String userId = StringUtils.trimToNull(values[2]);

        // Could not get a required value from the cookie
        if (userId == null || token == null || timestamp == null) {
            return null;
        }

        final String expectedData;
        try {
            expectedData = encryptData(createDataToEncrypt(userId, timestamp));
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CookieAuthenticationImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CookieAuthenticationImpl.class.getName()).log(Level.SEVERE, null, ex);
            return null;
        }

        // If Cookie token and Expected token don't match, return null
        if (!StringUtils.equals(token, expectedData)) {
            return null;
        }

        // TODO: Handle cookie timestamping more appropriately.

        // Check if the current time is greater than the acceptable cookie
        // expiry timestamp
        // long cookieTimestamp = Long.parseLong(timestamp);
        // if (System.currentTimeMillis() > cookieTimestamp) {
        //    return null;
        // }

        return new SimpleCredentials(userId, "".toCharArray());
    }

    /**
     *
     * @param request
     * @param response
     * @param cookieName
     * @return
     */
    @Override
    public boolean dropCredentials(HttpServletRequest request,
            HttpServletResponse response) {

        CookieUtil.dropCookies(request, response, cookieName);
        if(dropCookieRegexes != null && dropCookieRegexes.length > 0) {
            CookieUtil.dropCookiesByRegexArray(request, response, dropCookieRegexes);
        }
        return true;
    }

    @Override
    public boolean useAuthenticationFailed() {
        return false;
    }

    @Override
    public void authenticationFailed(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
        throw new UnsupportedOperationException("CookieAuthenticationImpl.useAuthenticationFailed() returns false.");
    }

    @Override
    public boolean useAuthenticationSucceeded() {
        return false;
    }

    @Override
    public boolean authenticationSucceeded(HttpServletRequest request, HttpServletResponse response, AuthenticationInfo authInfo) {
        throw new UnsupportedOperationException("CookieAuthenticationImpl.useAuthenticationSucceeded() returns false.");
    }

    /**
     * Add data to response to authenticate future session (usually a Cookie)
     *
     * @param request
     * @param response
     * @param authInfo
     * @return
     */
    @Override
    public boolean addCredentials(HttpServletRequest request,
            HttpServletResponse response, AuthenticationInfo authInfo) {
        int expiry = cookieExpiry;
        final String rememberMeKey = (String) rememberMe.getKey();

        boolean hasRememberMe =
            (StringUtils.isNotBlank(rememberMeKey)) &&
            (StringUtils.isNotBlank(request.getParameter(rememberMeKey)));

        if(hasRememberMe) {
            String expiryValue = request.getParameter(rememberMeKey);
            if(StringUtils.equals(expiryValue, (String) rememberMe.getValue())) {
                expiry = cookieRememberMeExpiry;
            }
        }

        final Cookie cookie = createSessionAuthenticationCookie(authInfo.getUser(), cookiePath, expiry);
        CookieUtil.addCookie(cookie, response);
        return true;
    }

    /**
     *
     * @param userId
     * @param cookiePath
     * @param expiry
     * @return
     */
    private Cookie createSessionAuthenticationCookie(String userId,
            String cookiePath, int expiry) {
        try {
            long expiriesAt = new Date().getTime();

            if(expiry > 0) {
                expiriesAt += (expiry * 1000); // seconds to millseconds
            }

            final String timestamp = String.valueOf(expiriesAt);
            String cookieData = createCookieData(userId, timestamp);

            Cookie cookie = new Cookie(cookieName, cookieData);
            cookie.setPath(cookiePath);
            cookie.setMaxAge(expiry); // in seconds

            return cookie;
        } catch (UnsupportedEncodingException ex) {
            Logger.getLogger(CookieAuthenticationImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(CookieAuthenticationImpl.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(CookieAuthenticationImpl.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    /**
     *
     * @param userId
     * @param token
     * @param timestamp
     * @return
     * @throws UnsupportedEncodingException
     */
    private String createCookieData(String userId, String timestamp) throws
            UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException {
        /* HmacSHA1(<secret>,<expirytime>@<userID>)@<expirytime>@<userID> */

        final String data = createPlainTextData(userId, timestamp);
        final String encyptedData = encryptData(createDataToEncrypt(userId, timestamp));

        String tmp = encyptedData + DATA_DELIMITER + data;
        tmp = new Base64(true).encodeToString(tmp.getBytes()).toString();

        return URLEncoder.encode(tmp, cookieEncoding);
    }


    private String createPlainTextData(String userId, String timestamp) {
        return timestamp + DATA_DELIMITER + userId;
    }

    private String createDataToEncrypt(String userId, String timestamp) {
        return secret + "," + createPlainTextData(userId, timestamp);
    }

    /**
     * Encrypt token data
     *
     * @param data
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    private String encryptData(String data) throws NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec keySpec = new SecretKeySpec(
                secret.getBytes(),
                encryptionType);

        Mac mac = Mac.getInstance(encryptionType);
        mac.init(keySpec);
        byte[] result = mac.doFinal(data.getBytes());
        return StringUtils.trim(new Base64(true).encodeToString(result));
    }

    private String[] splitCookieData(String data) {
        if(StringUtils.isBlank(data)) { return null; }
        return StringUtils.split(data, DATA_DELIMITER);
        /*
        String[] split = new String[3];

        int i = data.indexOf(DATA_DELIMITER);
        // No Delimiter exists anywhere in the string
        if(i < 0) { return null; }

        split[0] = data.substring(0, i);

        // Delimiter is the last character in the string, so return
        if((i + 1) >= data.length()) { return null; }

        data = data.substring(i + 1, data.length());
        i = data.indexOf(DATA_DELIMITER);

        // No Delimiters exist in the plain text portion of the data
        if(i < 0) { return split; }

        split[1] = data.substring(0, i);

        // Delimiter is the last character in the plain text portion of the data
        if((i + 1) >= data.length()) { return null; }

        split[2] = data.substring(i + 1, data.length());

        return split;
        */
    }


    @SuppressWarnings("unchecked")
    protected void activate(ComponentContext componentContext) {
        Dictionary properties = componentContext.getProperties();

        encryptionType = PropertiesUtil.toString(properties.get(PROP_ENCRYPTION_TYPE), DEFAULT_ENCRYPTION_TYPE);

        cookieName = PropertiesUtil.toString(properties.get(PROP_COOKIE_NAME), DEFAULT_COOKIE_NAME);

        cookiePath = PropertiesUtil.toString(properties.get(PROP_COOKIE_PATH), DEFAULT_COOKIE_PATH);

        cookieEncoding = PropertiesUtil.toString(properties.get(PROP_COOKIE_ENCODING), DEFAULT_COOKIE_ENCODING);

        secret = PropertiesUtil.toString(properties.get(PROP_COOKIE_SECRET), DEFAULT_COOKIE_SECRET);

        cookieExpiry = PropertiesUtil.toInteger(properties.get(PROP_COOKIE_EXPIRY), DEFAULT_COOKIE_EXPIRY);

        final long cookieRememberMeExpiryL = PropertiesUtil.toLong(properties.get(PROP_COOKIE_REMEMBER_ME_EXPIRY), DEFAULT_REMEMBER_ME_COOKIE_EXPIRY);
        cookieRememberMeExpiry = (int) (cookieRememberMeExpiryL * 86400); // Seconds in a day

        rememberMe = OsgiPropertyUtil.toSimpleEntry(PropertiesUtil.toString(properties.get(PROP_REMEMBER_ME), "remember-me"), ":");
    }

    protected void deactivate(ComponentContext componentContext) {

    }
}
