package org.romainlavabre.security.principal;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.List;

/**
 * Single place deciding the roles of a call, shared by the filter chain and Security.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public final class EffectiveRoles {

    private EffectiveRoles() {
    }


    /**
     * @param provider Null when the application declares none: the roles of the principal apply
     */
    public static List< String > of( Principal principal, EffectiveRolesProvider provider ) {
        if ( provider == null ) {
            return principal.getRoles();
        }

        List< String > roles = provider.getRoles( principal, currentRequest() );

        return roles != null ? roles : List.of();
    }


    /**
     * Spring Boot binds the request before the security filter chain runs.
     */
    private static HttpServletRequest currentRequest() {
        RequestAttributes attributes = RequestContextHolder.getRequestAttributes();

        if ( attributes instanceof ServletRequestAttributes servletRequestAttributes ) {
            return servletRequestAttributes.getRequest();
        }

        return null;
    }
}
