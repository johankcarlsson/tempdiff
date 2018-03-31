package org.rapidcontext.core.security.impl;

import java.util.logging.Logger;

import org.apache.commons.lang.time.DateUtils;
import org.rapidcontext.core.data.Dict;
import org.rapidcontext.core.security.SecurityContext;
import org.rapidcontext.core.security.SecurityContext.RealmType;
import org.rapidcontext.core.storage.Storage;
import org.rapidcontext.core.type.User;
import org.rapidcontext.core.web.Request;
import org.rapidcontext.util.BinaryUtil;

public class StorageSecurityContext implements SecurityContextInterface{

        /**
     * The class logger.
     */
    private static final Logger LOG =
        Logger.getLogger(SecurityContext.class.getName());

        /**
         * The realm type
         */
        private static final RealmType realmType = RealmType.DIGEST;


        @Override
        public void authorizeUser(Request request, Dict auth,
                        ThreadLocal<User> currentUser, Storage dataStorage)
                        throws Exception {

                String  uri = auth.getString("uri", request.getAbsolutePath());
        String  user = auth.getString("username", "");
        String  realm = auth.getString("realm", "");
        String  nonce = auth.getString("nonce", "");
        String  nc = auth.getString("nc", "");
        String  cnonce = auth.getString("cnonce", "");
        String  response = auth.getString("response", "");
        String  suffix;

        // Verify authentication response
        if (!User.DEFAULT_REALM.equals(realm)) {
            LOG.info(ip(request) + "Invalid authentication realm: " + realm);
            throw new SecurityException("Invalid authentication realm");
        }
        verifyNonce(nonce);
        suffix = ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" +
                 BinaryUtil.hashMD5(request.getMethod() + ":" + uri);
        SecurityContext.authHash(user, suffix, response);
        LOG.fine(ip(request) + "Valid authentication for " + user);

        }

        /**
     * Verifies that the specified nonce is sufficiently recently
     * generated to be acceptable.
     *
     * @param nonce          the nonce to check
     *
     * @throws SecurityException if the nonce was invalid
     */
    private void verifyNonce(String nonce) throws SecurityException {
        try {
            long since = System.currentTimeMillis() - Long.parseLong(nonce);
            if (since > DateUtils.MILLIS_PER_MINUTE * 240) {
                LOG.info("stale authentication one-off number");
                throw new SecurityException("stale authentication one-off number");
            }
        } catch (NumberFormatException e) {
            LOG.info("invalid authentication one-off number");
            throw new SecurityException("invalid authentication one-off number");
        }
    }

    /**
     * Returns an IP address tag suitable for logging.
     *
     * @param request        the request to use
     *
     * @return the IP address tag for logging
     */
    private String ip(Request request) {
        return "[" + request.getRemoteAddr() + "] ";
    }

        @Override
        public RealmType getRealmType() {
                return realmType;
        }

        @Override
        public Dict getAuthData(Request req) {
                return req.getAuthentication();
        }

}
