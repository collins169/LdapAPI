/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kedstudio.ldap.utils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.CommunicationException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import javax.naming.ldap.StartTlsRequest;
import javax.naming.ldap.StartTlsResponse;
import javax.net.ssl.*;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Hashtable;

/**
 *
 * @author fasyf
 */
public class ActiveDirectory {

    private static final Logger logger = LoggerFactory.getLogger(ActiveDirectory.class);
    private static final String[] userAttributes = {"distinguishedName", "cn", "name", "uid", "sn", "givenname", "memberOf", "samaccountname", "userPrincipalName"};

    public static LdapContext getConnection(String username, String password)
            throws NamingException {
        return getConnection(username, password, null, null);
    }

    public static LdapContext getConnection(String username, String password, String domainName)
            throws NamingException {
        return getConnection(username, password, domainName, null);
    }

    public static LdapContext getConnection(String username, String password, String domainName, String serverName)
            throws NamingException {
        if (domainName == null) {
            try {
                String fqdn = InetAddress.getLocalHost().getCanonicalHostName();
                if (fqdn.split("\\.").length > 1) {
                    domainName = fqdn.substring(fqdn.indexOf(".") + 1);
                }
            } catch (UnknownHostException e) {
            }
        }
        if (password != null) {
            password = password.trim();
            if (password.length() == 0) {
                password = null;
            }
        }
        Hashtable props = new Hashtable();
        String principalName = username + "@" + domainName;
        props.put("java.naming.security.principal", principalName);
        if (password != null) {
            props.put("java.naming.security.credentials", password);
        }
        String ldapURL = "ldap://" + (serverName == null ? domainName : new StringBuilder().append(serverName).append(".").append(domainName).toString()) + '/';
        props.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        props.put("java.naming.provider.url", ldapURL);
        try {
            return new InitialLdapContext(props, null);
        } catch (CommunicationException e) {
            logger.error(e.getMessage(),e);
            throw new NamingException("Failed to connect to " + domainName + (serverName == null ? "" : new StringBuilder().append(" through ").append(serverName).toString()));
        } catch (NamingException e) {
            logger.error(e.getExplanation(),e);
            throw new NamingException("Failed to authenticate " + username + "@" + domainName + (serverName == null ? "" : new StringBuilder().append(" through ").append(serverName).toString()));
        }
    }

    public static User getUser(String username, LdapContext context) {
        try {
            String domainName = null;
            if (username.contains("@")) {
                username = username.substring(0, username.indexOf("@"));
                domainName = username.substring(username.indexOf("@") + 1);
            } else if (username.contains("\\")) {
                username = username.substring(0, username.indexOf("\\"));
                domainName = username.substring(username.indexOf("\\") + 1);
            } else {
                String authenticatedUser = (String) context.getEnvironment().get("java.naming.security.principal");
                if (authenticatedUser.contains("@")) {
                    domainName = authenticatedUser.substring(authenticatedUser.indexOf("@") + 1);
                }
            }
            if (domainName != null) {
                String principalName = username + "@" + domainName;
                SearchControls controls = new SearchControls();
                controls.setSearchScope(2);
                controls.setReturningAttributes(userAttributes);
                NamingEnumeration<SearchResult> answer = context.search(toDC(domainName), "(& (userPrincipalName=" + principalName + ")(objectClass=user))", controls);
                if (answer.hasMore()) {
                    Attributes attr = ((SearchResult) answer.next()).getAttributes();
                    Attribute user = attr.get("userPrincipalName");
                    if (user != null) {
                        return new User(attr);
                    }
                }
            }
        } catch (NamingException e) {
            logger.error(e.getExplanation(),e);
        }
        return null;
    }

    public static User[] getUsers(LdapContext context)
            throws NamingException {
        ArrayList<User> users = new ArrayList();
        String authenticatedUser = (String) context.getEnvironment().get("java.naming.security.principal");
        if (authenticatedUser.contains("@")) {
            String domainName = authenticatedUser.substring(authenticatedUser.indexOf("@") + 1);
            SearchControls controls = new SearchControls();
            controls.setSearchScope(2);
            controls.setReturningAttributes(userAttributes);
            NamingEnumeration answer = context.search(toDC(domainName), "(objectClass=user)", controls);
            try {
                while (answer.hasMore()) {
                    Attributes attr = ((SearchResult) answer.next()).getAttributes();
                    Attribute user = attr.get("userPrincipalName");
                    if (user != null) {
                        users.add(new User(attr));
                    }
                }
            } catch (Exception e) {
                logger.error(e.getMessage(),e);
            }
        }
        return (User[]) users.toArray(new User[users.size()]);
    }

    private static String toDC(String domainName) {
        StringBuilder buf = new StringBuilder();
        for (String token : domainName.split("\\.")) {
            if (token.length() != 0) {
                if (buf.length() > 0) {
                    buf.append(",");
                }
                buf.append("DC=").append(token);
            }
        }
        return buf.toString();
    }

    public static class User {

        private String distinguishedName;
        private String userPrincipal;
        private String commonName;

        public User(Attributes attr)
                throws NamingException {
            this.userPrincipal = ((String) attr.get("userPrincipalName").get());
            this.commonName = ((String) attr.get("cn").get());
            this.distinguishedName = ((String) attr.get("distinguishedName").get());
        }

        public String getUserPrincipal() {
            return this.userPrincipal;
        }

        public String getCommonName() {
            return this.commonName;
        }

        public String getDistinguishedName() {
            return this.distinguishedName;
        }

        public String toString() {
            return getDistinguishedName();
        }

        public void changePassword(String oldPass, String newPass, boolean trustAllCerts, LdapContext context)
                throws IOException, NamingException {
            String dn = getDistinguishedName();

            StartTlsResponse tls = null;
            try {
                tls = (StartTlsResponse) context.extendedOperation(new StartTlsRequest());
            } catch (Exception e) {
                throw new IOException("Failed to establish SSL connection to the Domain Controller. Is LDAPS enabled?");
            }
            if (trustAllCerts) {
                tls.setHostnameVerifier(DO_NOT_VERIFY);
                SSLSocketFactory sf = null;
                try {
                    SSLContext sc = SSLContext.getInstance("TLS");
                    sc.init(null, TRUST_ALL_CERTS, null);
                    sf = sc.getSocketFactory();
                } catch (NoSuchAlgorithmException e) {
                } catch (KeyManagementException e) {
                }
                tls.negotiate(sf);
            } else {
                tls.negotiate();
            }
            try {
                ModificationItem[] modificationItems = new ModificationItem[2];
                modificationItems[0] = new ModificationItem(3, new BasicAttribute("unicodePwd", getPassword(oldPass)));
                modificationItems[1] = new ModificationItem(1, new BasicAttribute("unicodePwd", getPassword(newPass)));
                context.modifyAttributes(dn, modificationItems);
            } catch (InvalidAttributeValueException e) {
                String error = e.getMessage().trim();
                if ((error.startsWith("[")) && (error.endsWith("]"))) {
                    error = error.substring(1, error.length() - 1);
                }
                System.err.println(error);

                tls.close();
                throw new NamingException("New password does not meet Active Directory requirements. Please ensure that the new password meets password complexity, length, minimum password age, and password history requirements.");
            } catch (NamingException e) {
                tls.close();
                throw e;
            }
            tls.close();
        }

        private static final HostnameVerifier DO_NOT_VERIFY = new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        };
        private static TrustManager[] TRUST_ALL_CERTS = {new X509TrustManager() {
            public X509Certificate[] getAcceptedIssuers() {
                return null;
            }

            public void checkClientTrusted(X509Certificate[] certs, String authType) {
            }

            public void checkServerTrusted(X509Certificate[] certs, String authType) {
            }
        }};

        private byte[] getPassword(String newPass) {
            String quotedPassword = "\"" + newPass + "\"";

            char[] unicodePwd = quotedPassword.toCharArray();
            byte[] pwdArray = new byte[unicodePwd.length * 2];
            for (int i = 0; i < unicodePwd.length; i++) {
                pwdArray[(i * 2 + 1)] = ((byte) (unicodePwd[i] >>> '\b'));
                pwdArray[(i * 2 + 0)] = ((byte) (unicodePwd[i] & 0xFF));
            }
            return pwdArray;
        }
    }

    public static boolean authenticate(String username, String password, String domain) {
        try {
            //LdapContext ctx = getConnection(username, password, "fabl.com.gh");
            LdapContext ctx = getConnection(username, password, domain);
            ctx.close();
            return true;
        } catch (NamingException e) {
            logger.error(e.getExplanation(),e);
            return false;
        }
    }

    public static boolean isValidUser(String defaultUser, String defaultPass, String domain, String username) {
        try {
            //LdapContext ctx = getConnection("channelaudit", "channel@789", "fabl.com.gh");
            //LdapContext ctx = getConnection(defaultUser, defaultPass, "fabl.com.gh");
            LdapContext ctx = getConnection(defaultUser, defaultPass, domain);
            User user = getUser(username, ctx);
            ctx.close();
            return (user != null);
            //System.out.println(true);
        } catch (Exception e) {
            logger.error(e.getMessage(),e);
            return false;
        }
    }

    public static void main(String[] args) {
        try {
            LdapContext ctx = getConnection("channelaudit", "channel*789", "fabl.com.gh");
            //boolean res = authenticate("channelaudit", "channel*789");
            User user = getUser("channeluser", ctx);
            ctx.close();
            //System.out.println(res);
            System.out.println((user != null));
//            System.out.println(user.getUserPrincipal());
//            System.out.println(user.getCommonName());
//            System.out.println(user.getDistinguishedName());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
