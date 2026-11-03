package org.romainlavabre.security.principal;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class EffectiveRolesTest {

    private static final Principal PRINCIPAL = new Principal(
            "sub", Principal.Type.USER, List.of( "ROLE_ADMIN" ), Map.of( "tenant_roles", Map.of( "12", List.of( "ROLE_OWNER" ) ) ), "user@example.fr"
    );


    @After
    public void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }


    /**
     * An application declaring no provider keeps the behaviour of 5.2.0.
     */
    @Test
    public void it_applies_the_roles_of_the_principal_without_provider() {
        Assert.assertEquals( List.of( "ROLE_ADMIN" ), EffectiveRoles.of( PRINCIPAL, null ) );
    }


    @Test
    public void it_applies_the_roles_the_provider_reads_from_the_current_request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader( "X-Tenant", "12" );
        RequestContextHolder.setRequestAttributes( new ServletRequestAttributes( request ) );

        ProviderSpy provider = new ProviderSpy();

        Assert.assertEquals( List.of( "ROLE_ADMIN", "ROLE_OWNER" ), EffectiveRoles.of( PRINCIPAL, provider ) );
        Assert.assertSame( request, provider.requests.get( 0 ) );
    }


    @Test
    public void it_gives_no_request_to_the_provider_outside_an_http_request() {
        ProviderSpy provider = new ProviderSpy();

        Assert.assertEquals( List.of( "ROLE_ADMIN" ), EffectiveRoles.of( PRINCIPAL, provider ) );
        Assert.assertEquals( 1, provider.requests.size() );
        Assert.assertNull( provider.requests.get( 0 ) );
    }


    /**
     * A provider answering null must deny, not fail every call with a 500.
     */
    @Test
    public void it_applies_no_role_when_the_provider_answers_null() {
        Assert.assertEquals( List.of(), EffectiveRoles.of( PRINCIPAL, ( principal, request ) -> null ) );
    }


    /**
     * Global roles, plus the ones held in the tenant the request names.
     */
    private static class ProviderSpy implements EffectiveRolesProvider {
        private final List< HttpServletRequest > requests = new ArrayList<>();


        @Override
        @SuppressWarnings( "unchecked" )
        public List< String > getRoles( Principal principal, HttpServletRequest request ) {
            requests.add( request );

            List< String > roles = new ArrayList<>( principal.getRoles() );

            if ( request == null || request.getHeader( "X-Tenant" ) == null ) {
                return roles;
            }

            Map< String, List< String > > tenantRoles = ( Map< String, List< String > > ) principal.getAttributes().get( "tenant_roles" );

            roles.addAll( tenantRoles.getOrDefault( request.getHeader( "X-Tenant" ), List.of() ) );

            return roles;
        }
    }
}
