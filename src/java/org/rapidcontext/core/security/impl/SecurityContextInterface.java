package org.rapidcontext.core.security.impl;

import org.rapidcontext.core.data.Dict;
import org.rapidcontext.core.security.SecurityContext.RealmType;
import org.rapidcontext.core.storage.Storage;
import org.rapidcontext.core.type.User;
import org.rapidcontext.core.web.Request;

public interface SecurityContextInterface {
        public void authorizeUser(Request request, Dict auth, ThreadLocal<User> currentUser, Storage dataStorage) throws SecurityException, Exception;
        public RealmType getRealmType();
        public Dict getAuthData(Request req);
}
