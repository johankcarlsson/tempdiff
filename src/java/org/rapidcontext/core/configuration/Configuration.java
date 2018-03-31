package org.rapidcontext.core.configuration;

import org.apache.commons.configuration.ConfigurationException;
import org.apache.commons.configuration.PropertiesConfiguration;

public class Configuration {

        private static Configuration INSTANCE = null;
        private static PropertiesConfiguration configuration = null;
        private static enum propertyKeys {
                AD_URLS ("ad.urls"),
                AD_SEARCH_BASE ("ad.searchBase"),
                AD_SEARCH_FILTER ("ad.searchFilter"),
                AD_TIMEOUT ("ad.timeout"),
                LOGIN_MODULE ("login.module"),
                AD_DOMAIN ("ad.domain");

                private final String name;

                private propertyKeys(String name){
                        this.name = name;
                }

                public String toString() {
                        return name;
                }
        }


        //Prevent Instantiation
        private Configuration() throws ConfigurationException{
                configuration = new PropertiesConfiguration("rapidcontext.properties");
        }

        public static Configuration getInstance() throws ConfigurationException{
                if(INSTANCE == null){
                        INSTANCE = new Configuration();
                }

                return INSTANCE;
        }

        public String[] adUrls(){
                return configuration.getStringArray(propertyKeys.AD_URLS.name);
        }

        public String adSearchBase(){
                return configuration.getString(propertyKeys.AD_SEARCH_BASE.name);
        }

        public String adSearchFilter(){
                return configuration.getString(propertyKeys.AD_SEARCH_FILTER.name);
        }

        public int adTimeout(){
                return configuration.getInt(propertyKeys.AD_TIMEOUT.name);
        }

        public String loginModule(){
                return configuration.getString(propertyKeys.LOGIN_MODULE.name);
        }

        public String adDomain(){
                return configuration.getString(propertyKeys.AD_DOMAIN.name);
        }

}
