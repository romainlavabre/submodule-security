package org.romainlavabre.security.principal;

import jakarta.servlet.http.HttpServletRequest;

import java.util.List;

/**
 * Optional lookup layer, supplied by the host application: the roles that apply to one call.
 * <p>
 * For an application whose roles depend on the call and not only on the caller, eg roles held in a
 * tenant picked by a header. The module knows nothing about such a context: the application reads it
 * from the request, and the data it needs from the attributes of the principal, cached with it.
 * <p>
 * Used by the filter chain and by Security.getRoles() / hasRole() alike, so both always agree. Without
 * such a bean, the roles of the principal apply, unchanged.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface EffectiveRolesProvider {

    /**
     * Called on every authorization check: it must answer from memory, never from a database.
     *
     * @param principal The resolved caller, never null
     * @param request   The current request, null outside an HTTP request
     * @return Role names, ROLE_ prefixed. Null or empty denies every secured endpoint
     */
    List< String > getRoles( Principal principal, HttpServletRequest request );
}
