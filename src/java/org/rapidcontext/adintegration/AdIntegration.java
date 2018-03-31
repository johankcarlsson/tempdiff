package org.rapidcontext.adintegration;

import java.util.Hashtable;
import java.util.logging.Logger;

import javax.naming.AuthenticationException;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.commons.configuration.ConfigurationException;
import org.rapidcontext.core.configuration.Configuration;

/**
 * A Active Directory LDAP integration class.
 * @author persson21
 *
 */
public class AdIntegration {
        private static final Logger LOG = Logger.getLogger(AdIntegration.class
                        .getName());
        private String username;
        private Hashtable<String, String> env;
        private InitialDirContext ctx;
        private SearchResult searchresult;
//      private static String[] serverUrl = { "ldap://localhost:10270", "ldap://rodc02.omaccess.net:389" };
        private Configuration configuration = null;

        private void search() throws NamingException {
                //              String searchBase = "OU=Nordic,DC=3internal,DC=local";
//              String searchFilter = "(&(objectCategory=user)(sAMAccountName="
//                              + username + "))";
                String searchFilter = String.format(configuration.adSearchFilter(), username);
                SearchControls sCtrl = new SearchControls();
                sCtrl.setTimeLimit(configuration.adTimeout());
                sCtrl.setSearchScope(SearchControls.SUBTREE_SCOPE);

                NamingEnumeration<SearchResult> results = ctx.search(configuration.adSearchBase(),
                                searchFilter, sCtrl);
                searchresult = results.nextElement();

        }

        public AdIntegration(){
                try{
                configuration = Configuration.getInstance();
                }catch(ConfigurationException e){
                        throw new SecurityException(e);
                }
        }


        /**
         * @param username      the username to authenticate
         * @param password      the password provided
         * @return true if user is successfully authenticated,
         *                      false if provided credentials does not correspond to the credentials stored in Active Directory
         * @throws SecurityException if no connection to LDAP server was available
         */
        public boolean validAuthentication(String username, String password) throws SecurityException {
                this.username = username;
                String msg;
                env = new Hashtable<String, String>();
                env.put(Context.INITIAL_CONTEXT_FACTORY,
                                "com.sun.jndi.ldap.LdapCtxFactory");
                env.put(Context.SECURITY_AUTHENTICATION, "simple");
                env.put(Context.SECURITY_PRINCIPAL, username + configuration.adDomain());
                env.put(Context.SECURITY_CREDENTIALS, password);
                env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(configuration.adTimeout()));

                for (String url : configuration.adUrls()) {
                        env.put(Context.PROVIDER_URL, url);
                        try {
                                ctx = new InitialDirContext(env);
                                search();
                                ctx.close();
                                return true;
                        } catch (AuthenticationException ex) {
                                msg = "invalid user or password";
                                LOG.info("Failed authentication: " + msg);
                                return false;
                        } catch (NamingException e) {
                                msg = "Failed to bind against Active Directory on " + url + ".";
                                LOG.info(msg);
                        }
                }
                msg = "No LDAP server available.";
                LOG.info(msg);
                throw new SecurityException(msg);
        }

        /**
         * @param grouplist a list of groups search
         * @return      true if user is member of any group that was provided in grouplist,
         *                      false if user was not member of any of the groups provided in searchlist
         * @throws NamingException
         */
        public boolean getMemberOf(String[] grouplist) throws NamingException {
                NamingEnumeration<?> all = searchresult.getAttributes().get("memberOf")
                                .getAll();
                while (all.hasMoreElements()) {
                        String commonName = all.nextElement().toString();
                        for (String group : grouplist) {
                                String pattern = "^[Cc][Nn]=" + group.trim() + ",.*";
                                if (commonName.matches(pattern))
                                        return true;
                        }
                }
                return false;
        }

        /**
         * @return      Full name of authenticated user if found in Active Directory
         */
        public String getFullName(){
                String fullname = "";
                NamingEnumeration<?> all;
                try {
                        all = searchresult.getAttributes().get("displayName").getAll();
                        fullname = all.nextElement().toString().trim();
                } catch (NamingException e) {
                        LOG.info("Failed to get username from Active Directory: " + e.getMessage() + ".");
                }
                return fullname;
        }
}
