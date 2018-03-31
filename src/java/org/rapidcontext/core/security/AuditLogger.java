package org.rapidcontext.core.security;

import org.apache.log4j.Logger;
import org.apache.log4j.MDC;
import org.rapidcontext.core.type.Session;

public class AuditLogger {

        private static final Logger auditLogger = Logger.getLogger("audit");

        public AuditLogger(){

        }

        public void info(String message, String action){
        MDC.put("session_id", Session.activeSession.get().toString());
        MDC.put("action", action);
        auditLogger.info(message);
        MDC.remove("session_id");
        MDC.remove("action");
    }
}
