/*
 * RapidContext <http://www.rapidcontext.com/>
 * Copyright (c) 2007-2012 Per Cederberg. All rights reserved.
 *
 * This program is free software: you can redistribute it and/or
 * modify it under the terms of the BSD license.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 * See the RapidContext LICENSE.txt file for more details.
 */

package org.rapidcontext.core.security.impl;

import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.naming.NamingException;

import org.apache.commons.lang.time.DateUtils;
import org.rapidcontext.adintegration.AdIntegration;
import org.rapidcontext.core.data.Dict;
import org.rapidcontext.core.proc.Procedure;
import org.rapidcontext.core.security.Restricted;
import org.rapidcontext.core.security.SecurityContext.RealmType;
import org.rapidcontext.core.storage.Path;
import org.rapidcontext.core.storage.Storage;
import org.rapidcontext.core.storage.StorageException;
import org.rapidcontext.core.type.Role;
import org.rapidcontext.core.type.Session;
import org.rapidcontext.core.type.User;
import org.rapidcontext.core.web.Request;
import org.rapidcontext.util.BinaryUtil;

/**
 * The application security context. This class provides static methods for
 * authentication and resource authorization. It stores the currently
 * authenticated user in a thread-local storage, so user credentials must be
 * provided separately for each execution thread. It is important that the
 * manager is initialized before any authentication calls are made, or they will
 * fail.
 *
 * @author Per Cederberg
 * @version 1.0
 */
public class ADSecurityContext implements SecurityContextInterface{

        /**
         * The class logger.
         */
        private static final Logger LOG = Logger.getLogger(ADSecurityContext.class
                        .getName());

        /**
         * The realm type
         */
        private static final RealmType realmType = RealmType.BASIC;

        /**
         * A local method for checking group permissions in Active Directory and
         * "translating" them into the Roles employed in RapidContext. It retrieves
         * existing Roles from storage, gets the user groups from AD and then matches
         * groups found with the group variable in each Role. If an AD group is found
         * to match one of the group names in a given Role, the user is granted that Role.
         *
         * @author skogsberg02, persson21
         * @category    AD Integration
         * @param ad
         *                              the AdIntegration instantiation
         * @param user
         *                              the currently authenticated user
         * @throws SecurityException
         *                              if no groups were found in AD
         */
        private static void setPermissions(AdIntegration ad, User user, Storage dataStorage)
                        throws SecurityException {
                String msg;
                ArrayList<String> roleList = new ArrayList<String>();

                try {
                        Role[] storedRoles = Role.findAll(dataStorage);

                        if(user.isAdmin()){
                                roleList.add("admin");
                        }
                        for (Role role : storedRoles) {
                                String searchParam = role.group();
                                if (searchParam != null && searchParam != "") {
                                        if (ad.getMemberOf(searchParam.split(","))) {
                                                roleList.add(role.id());
                                        } else {
                                                msg = "Unable to retrieve groups: did not find "
                                                                + searchParam;
                                                throw new SecurityException(msg);
                                        }
                                }
                        }
                        //Moves the roles from List to Array in order to set roles for user.
                        String[] roles = new String[roleList.size()];
                        for (String role : roleList) {
                                roles[roleList.indexOf(role)] = role;
                        }
                        user.setRoles(roles);
                        User.store(dataStorage, user);
                } catch (StorageException e) {
                        LOG.info("Storage Exception: " + e.getMessage());
                } catch (NamingException e) {
                        LOG.info("LDAP error: " + e.getMessage());
                }
        }

        @Override
        public void authorizeUser(Request request, Dict auth, ThreadLocal<User> currentUser, Storage dataStorage) throws SecurityException {
                String username = auth.getString("username", "");
                String pass = auth.getString("password", "");
                User user = User.find(dataStorage, username);
                String msg;
                AdIntegration ad = new AdIntegration();

                if (ad.validAuthentication(username, pass)) {
                        if (user == null) {
                                msg = "user " + username + " does not exist";
                                user = new User(username);
                                user.setName(ad.getFullName());
                                LOG.info("Null user: " + msg + ", creating new user");
                        } else if (!user.isEnabled()) {
                                msg = "user " + username + " is disabled";
                                LOG.info("failed authentication: " + msg);
                                throw new SecurityException(msg);
                        }
                        msg = "user " + username.toLowerCase() + " succesfully authenticated";
                        LOG.info(msg);
                        setPermissions(ad, user, dataStorage);
                        currentUser.set(user);
                } else {
                        msg = "invalid username or password for user " + username;
                        LOG.info("failed authentication: " + msg);
                        user = null;
                        throw new SecurityException(msg);
                }
        }

        @Override
        public RealmType getRealmType() {
                return realmType;
        }

        @Override
        public Dict getAuthData(Request req) {
                return req.getBasicAuthentication();
        }
}
