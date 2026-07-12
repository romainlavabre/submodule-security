package org.romainlavabre.security.config;

import org.romainlavabre.security.exception.NotInitializedException;

import java.util.*;

public class SecurityConfigurer {
    /**
     * Covers both /auth/refresh and /auth/revoke, which need to replay the refresh token.
     */
    private static final String DEFAULT_SESSION_COOKIE_PATH = "/auth";

    private static SecurityConfigurer INSTANCE;

    private final List< String >        publicEndpoints     = new ArrayList<>();
    private final Map< String, String > securedEndpoints    = new HashMap<>();
    private final List< InMemoryUser >  inMemoryUsers       = new ArrayList<>();
    private final List< String >        allowedClientIds    = new ArrayList<>();
    private final List< String >        sameSiteNoneDomains = new ArrayList<>();
    private final Map< String, String > issuers             = new LinkedHashMap<>();
    private final Map< String, String > clientSecrets       = new HashMap<>();

    private String cookieDomain;
    private String cognitoUrl;
    private String reverseProxyPrefix = "";
    private String userPoolId;
    private String awsRegion;
    private String awsAccessKey;
    private String awsSecretAccessKey;


    public SecurityConfigurer() {
        INSTANCE = this;
    }


    public static SecurityConfigurer get() {
        if ( INSTANCE == null ) {
            throw new NotInitializedException();
        }

        return INSTANCE;
    }


    public static SecurityConfigurer init() {
        return new SecurityConfigurer();
    }


    protected List< String > getPublicEndpoint() {
        return publicEndpoints;
    }


    public SecurityConfigurer addPublicEndpoint( String publicEndpoint ) {
        publicEndpoints.add( publicEndpoint );

        return this;
    }


    public Map< String, String > getSecuredEndpoints() {
        return securedEndpoints;
    }


    public SecurityConfigurer addSecuredEndpoint( String matcher, String role ) {
        securedEndpoints.put( matcher, role );

        return this;
    }


    protected List< InMemoryUser > getInMemoryUsers() {
        return inMemoryUsers;
    }


    public SecurityConfigurer addInMemoryUserWithHttpBasic( InMemoryUser inMemoryUser ) {
        inMemoryUsers.add( inMemoryUser );

        return this;
    }


    /**
     * @return Issuer as key, jwks uri as value. A null value means the jwks uri is discovered from the issuer
     * well known configuration.
     */
    public Map< String, String > getIssuers() {
        return issuers;
    }


    /**
     * The jwks uri is discovered from the issuer well known configuration, at startup.
     *
     * @param issuer eg https://cognito-idp.eu-west-3.amazonaws.com/eu-west-3_XXXXXXXX
     */
    public SecurityConfigurer addIssuer( String issuer ) {
        return addIssuer( issuer, null );
    }


    /**
     * @param issuer  eg https://cognito-idp.eu-west-3.amazonaws.com/eu-west-3_XXXXXXXX
     * @param jwksUri eg https://cognito-idp.eu-west-3.amazonaws.com/eu-west-3_XXXXXXXX/.well-known/jwks.json
     */
    public SecurityConfigurer addIssuer( String issuer, String jwksUri ) {
        issuers.put( issuer, jwksUri );

        return this;
    }


    public List< String > getAllowedClientIds() {
        return allowedClientIds;
    }


    /**
     * A Cognito access token carries no aud claim, client_id stands for it. When at least one client id is
     * registered, any token issued for another client is rejected.
     */
    public SecurityConfigurer addAllowedClientId( String clientId ) {
        allowedClientIds.add( clientId );

        return this;
    }


    public String getClientSecret( String clientId ) {
        return clientSecrets.get( clientId );
    }


    /**
     * Secret of a confidential client, used to exchange an authorization code and to refresh a session.
     * It never leaves the server.
     */
    public SecurityConfigurer addClient( String clientId, String clientSecret ) {
        clientSecrets.put( clientId, clientSecret );

        return this;
    }


    public String getCognitoUrl() {
        return cognitoUrl;
    }


    /**
     * @param cognitoUrl Base url of the hosted ui, eg https://my-domain.auth.eu-west-3.amazoncognito.com
     */
    public SecurityConfigurer setCognitoUrl( String cognitoUrl ) {
        this.cognitoUrl = cognitoUrl;

        return this;
    }


    public List< String > getSameSiteNoneDomains() {
        return sameSiteNoneDomains;
    }


    /**
     * Cookies are sent with SameSite=None on this domain, Strict on any other one.
     */
    public SecurityConfigurer addSameSiteNoneDomain( String domain ) {
        sameSiteNoneDomains.add( domain );

        return this;
    }


    public String getCookieDomain() {
        return cookieDomain;
    }


    public SecurityConfigurer setCookieDomain( String cookieDomain ) {
        this.cookieDomain = cookieDomain;

        return this;
    }


    public String getReverseProxyPrefix() {
        return reverseProxyPrefix;
    }


    /**
     * Prefix added by a reverse proxy in front of the backend, eg /api when the app is served under
     * https://host/api. The proxy strips it before forwarding, so the endpoints stay unprefixed
     * internally, but the browser addresses them under the prefix. Cookie paths must therefore carry
     * it to be replayed. Leave it null or blank when there is no proxy prefix.
     */
    public SecurityConfigurer setReverseProxyPrefix( String reverseProxyPrefix ) {
        this.reverseProxyPrefix = normalizePrefix( reverseProxyPrefix );

        return this;
    }


    /**
     * Path scoping a cookie to the whole application, eg / without a proxy prefix, /api with one.
     */
    public String getRootCookiePath() {
        return reverseProxyPrefix.isBlank() ? "/" : reverseProxyPrefix;
    }


    /**
     * Path scoping a cookie to the session endpoints (/auth/refresh and /auth/revoke), eg /auth
     * without a proxy prefix, /api/auth with one.
     */
    public String getSessionCookiePath() {
        return reverseProxyPrefix + DEFAULT_SESSION_COOKIE_PATH;
    }


    /**
     * Ensures a leading slash and drops any trailing one, so "api", "/api" and "/api/" all yield
     * "/api", while null or blank yields "" (no prefix).
     */
    private static String normalizePrefix( String prefix ) {
        if ( prefix == null || prefix.isBlank() ) {
            return "";
        }

        String normalized = prefix.trim();

        if ( !normalized.startsWith( "/" ) ) {
            normalized = "/" + normalized;
        }

        while ( normalized.endsWith( "/" ) ) {
            normalized = normalized.substring( 0, normalized.length() - 1 );
        }

        return normalized;
    }


    public String getUserPoolId() {
        return userPoolId;
    }


    /**
     * Required to administrate the identities, eg eu-west-3_XXXXXXXX
     */
    public SecurityConfigurer setUserPoolId( String userPoolId ) {
        this.userPoolId = userPoolId;

        return this;
    }


    public String getAwsRegion() {
        return awsRegion;
    }


    /**
     * Region of the user pool, eg eu-west-3
     */
    public SecurityConfigurer setAwsRegion( String awsRegion ) {
        this.awsRegion = awsRegion;

        return this;
    }


    public String getAwsAccessKey() {
        return awsAccessKey;
    }


    public String getAwsSecretAccessKey() {
        return awsSecretAccessKey;
    }


    /**
     * Credentials of the iam user allowed to administrate the user pool. When they are not set, the default
     * aws credentials provider chain is used, which covers an instance profile or an irsa role.
     */
    public SecurityConfigurer setAwsCredentials( String awsAccessKey, String awsSecretAccessKey ) {
        this.awsAccessKey       = awsAccessKey;
        this.awsSecretAccessKey = awsSecretAccessKey;

        return this;
    }


    public void build() {
    }
}
