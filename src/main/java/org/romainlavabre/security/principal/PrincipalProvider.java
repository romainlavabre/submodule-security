package org.romainlavabre.security.principal;

/**
 * Lookup layer of the authorization data, supplied by the host application.
 * <p>
 * The identity provider knows nothing but the email: roles and attributes live in the tables of the
 * application, which is the only one able to tell who a sub or a client id stands for. The module
 * ships no implementation, the application must declare exactly one bean.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface PrincipalProvider {

    /**
     * @param idpId The sub carried by the token, the Kratos identity id
     * @return null when no identity matches
     */
    Principal findIdentity( String idpId );


    /**
     * @param clientId The client id carried by the token, the Hydra client id
     * @return null when no client matches
     */
    Principal findClient( String clientId );
}
