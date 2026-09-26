package org.romainlavabre.security.config;

import org.romainlavabre.security.exception.NotInitializedException;

import java.util.*;

public class SecurityConfigurer {
    /**
     * Covers /auth/login/verify, /auth/refresh and /auth/logout, which need to replay the flow or the
     * session token.
     */
    private static final String DEFAULT_SESSION_COOKIE_PATH = "/auth";

    private static final long DEFAULT_PRINCIPAL_CACHE_MAX_SIZE    = 20_000;
    private static final long DEFAULT_PRINCIPAL_CACHE_TTL_SECONDS = 300;

    private static SecurityConfigurer INSTANCE;

    private final List< String >        publicEndpoints     = new ArrayList<>();
    private final Map< String, String > securedEndpoints    = new HashMap<>();
    private final List< InMemoryUser >  inMemoryUsers       = new ArrayList<>();
    private final List< String >        sameSiteNoneDomains = new ArrayList<>();
    private final Map< String, String > issuers             = new LinkedHashMap<>();
    private final Map< String, String > issuersWithJwks     = new LinkedHashMap<>();

    private String cookieDomain;
    private String reverseProxyPrefix = "";
    private String  audience;
    private boolean clientScopesRequired;
    private String  clientScopePrefix;
    private String kratosPublicUrl;
    private String kratosAdminUrl;
    private String kratosTokenizeAs;
    private String hydraAdminUrl;
    private long   principalCacheMaxSize    = DEFAULT_PRINCIPAL_CACHE_MAX_SIZE;
    private long   principalCacheTtlSeconds = DEFAULT_PRINCIPAL_CACHE_TTL_SECONDS;


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
     * @param issuer eg http://hydra:4444/
     */
    public SecurityConfigurer addIssuer( String issuer ) {
        return addIssuer( issuer, null );
    }


    /**
     * An issuer publishing its keys over HTTP, typically Hydra.
     *
     * @param issuer  eg http://hydra:4444/
     * @param jwksUri eg http://hydra:4444/.well-known/jwks.json
     */
    public SecurityConfigurer addIssuer( String issuer, String jwksUri ) {
        issuers.put( issuer, jwksUri );

        return this;
    }


    /**
     * @return Issuer as key, json web key set as value
     */
    public Map< String, String > getIssuersWithJwks() {
        return issuersWithJwks;
    }


    /**
     * An issuer whose public keys are provided statically, typically the Kratos tokenizer, which
     * publishes no jwks endpoint. No HTTP call is made, neither at startup nor later.
     *
     * @param issuer   eg http://kratos:4433/
     * @param jwksJson The public json web key set, eg {"keys":[{"kty":"RSA",...}]}. Never the private one.
     */
    public SecurityConfigurer addIssuerWithJwks( String issuer, String jwksJson ) {
        issuersWithJwks.put( issuer, jwksJson );

        return this;
    }


    public String getAudience() {
        return audience;
    }


    /**
     * When set, a token whose aud claim does not contain this value is rejected, whatever its issuer.
     *
     * @param audience eg marea
     */
    public SecurityConfigurer setAudience( String audience ) {
        this.audience = audience;

        return this;
    }


    public boolean isClientScopesRequired() {
        return clientScopesRequired;
    }


    /**
     * A client_credentials token must then carry the configured audience, and the scope
     * {@code <prefix>:read} on GET, HEAD and OPTIONS, {@code <prefix>:write} on any other method. A user
     * token is never concerned. Requires setAudience().
     */
    public SecurityConfigurer requireClientScopes() {
        this.clientScopesRequired = true;

        return this;
    }


    /**
     * @return The prefix of the client scopes, the audience when none was set
     */
    public String getClientScopePrefix() {
        return clientScopePrefix != null && !clientScopePrefix.isBlank() ? clientScopePrefix : audience;
    }


    /**
     * @param clientScopePrefix eg marea, for the scopes marea:read and marea:write
     */
    public SecurityConfigurer setClientScopePrefix( String clientScopePrefix ) {
        this.clientScopePrefix = clientScopePrefix;

        return this;
    }


    public String getKratosPublicUrl() {
        return kratosPublicUrl;
    }


    /**
     * Required by /auth/**, which drives the Kratos login flow.
     *
     * @param kratosPublicUrl eg http://kratos:4433, on the internal network
     */
    public SecurityConfigurer setKratosPublicUrl( String kratosPublicUrl ) {
        this.kratosPublicUrl = kratosPublicUrl;

        return this;
    }


    public String getKratosAdminUrl() {
        return kratosAdminUrl;
    }


    /**
     * Required to administrate the identities and to extend a session.
     *
     * @param kratosAdminUrl eg http://kratos:4434, on the internal network, never exposed
     */
    public SecurityConfigurer setKratosAdminUrl( String kratosAdminUrl ) {
        this.kratosAdminUrl = kratosAdminUrl;

        return this;
    }


    public String getKratosTokenizeAs() {
        return kratosTokenizeAs;
    }


    /**
     * @param kratosTokenizeAs Name of the Kratos tokenizer template turning a session into a JWT, eg jwt_user_v1
     */
    public SecurityConfigurer setKratosTokenizeAs( String kratosTokenizeAs ) {
        this.kratosTokenizeAs = kratosTokenizeAs;

        return this;
    }


    public String getHydraAdminUrl() {
        return hydraAdminUrl;
    }


    /**
     * Required to administrate the clients.
     *
     * @param hydraAdminUrl eg http://hydra:4445, on the internal network, never exposed
     */
    public SecurityConfigurer setHydraAdminUrl( String hydraAdminUrl ) {
        this.hydraAdminUrl = hydraAdminUrl;

        return this;
    }


    public long getPrincipalCacheMaxSize() {
        return principalCacheMaxSize;
    }


    /**
     * Upper bound of the principals kept in memory, 20 000 by default.
     */
    public SecurityConfigurer setPrincipalCacheMaxSize( long principalCacheMaxSize ) {
        this.principalCacheMaxSize = principalCacheMaxSize;

        return this;
    }


    public long getPrincipalCacheTtlSeconds() {
        return principalCacheTtlSeconds;
    }


    /**
     * Delay before a change of roles is seen by an already cached caller, 300 seconds by default.
     */
    public SecurityConfigurer setPrincipalCacheTtlSeconds( long principalCacheTtlSeconds ) {
        this.principalCacheTtlSeconds = principalCacheTtlSeconds;

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
     * Path scoping a cookie to the session endpoints (/auth/**), eg /auth without a proxy prefix,
     * /api/auth with one.
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


    /**
     * Fails fast on a configuration that would let every client through or none.
     */
    public void build() {
        if ( clientScopesRequired && ( audience == null || audience.isBlank() ) ) {
            throw new IllegalStateException( "requireClientScopes() needs an audience, use SecurityConfigurer.setAudience()" );
        }
    }
}
