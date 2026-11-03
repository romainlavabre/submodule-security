package org.romainlavabre.security.config;

import org.junit.After;
import org.junit.Assert;
import org.junit.Test;
import org.romainlavabre.security.principal.Principal;
import org.romainlavabre.security.principal.PrincipalResolver;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * The authorities the filter chain grants: the roles of the principal, or those of the provider.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class SecurityEffectiveRolesTest {

    private static final Jwt JWT = Jwt.withTokenValue( "token" ).header( "alg", "RS256" ).claim( "sub", "sub" ).build();


    @After
    public void tearDown() {
        RequestContextHolder.resetRequestAttributes();
    }


    @Test
    public void it_grants_the_roles_of_the_principal_without_provider() {
        Security security = new Security( resolver() );

        Assert.assertEquals( List.of( "ROLE_ADMIN" ), authorities( security ) );
    }


    @Test
    public void it_grants_the_roles_of_the_provider_for_the_current_request() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader( "X-Tenant", "12" );
        RequestContextHolder.setRequestAttributes( new ServletRequestAttributes( request ) );

        Security security = new Security( resolver() );
        security.setEffectiveRolesProvider( ( principal, current ) ->
                "12".equals( current.getHeader( "X-Tenant" ) ) ? List.of( "ROLE_OWNER" ) : List.of()
        );

        Assert.assertEquals( List.of( "ROLE_OWNER" ), authorities( security ) );
    }


    @Test
    public void it_keeps_the_spaces_opened_to_several_roles_in_declaration_order() {
        SecurityConfigurer securityConfigurer = SecurityConfigurer
                .init()
                .addSecuredEndpoint( "/company/management/**", "ROLE_OWNER", "ROLE_OFFICE" )
                .addSecuredEndpoint( "/company/billing/**", "ROLE_OWNER", "ROLE_ACCOUNTANT" )
                .addSecuredEndpoint( "/company/**", "ROLE_COMPANY_MEMBER" );

        Assert.assertEquals( List.of( "/company/management/**", "/company/billing/**" ), new ArrayList<>( securityConfigurer.getSecuredEndpointsWithAnyRole().keySet() ) );
        Assert.assertEquals( List.of( "ROLE_OWNER", "ROLE_OFFICE" ), securityConfigurer.getSecuredEndpointsWithAnyRole().get( "/company/management/**" ) );
        Assert.assertEquals( Map.of( "/company/**", "ROLE_COMPANY_MEMBER" ), securityConfigurer.getSecuredEndpoints() );
    }


    @Test
    public void it_refuses_a_space_opened_to_no_role() {
        Assert.assertThrows( IllegalArgumentException.class, () -> SecurityConfigurer.init().addSecuredEndpoint( "/company/**", new String[ 0 ] ) );
    }


    private List< String > authorities( Security security ) {
        AbstractAuthenticationToken authentication = security.jwtAuthenticationConverter().convert( JWT );
        List< String >              authorities    = new ArrayList<>();

        // Spring Security also grants the authentication factor (FACTOR_BEARER), which is not a role
        for ( GrantedAuthority authority : authentication.getAuthorities() ) {
            if ( authority.getAuthority().startsWith( "ROLE_" ) ) {
                authorities.add( authority.getAuthority() );
            }
        }

        return authorities;
    }


    private PrincipalResolver resolver() {
        return new PrincipalResolver() {
            @Override
            public Principal resolve( Jwt jwt ) {
                return resolve( jwt.getClaims() );
            }


            @Override
            public Principal resolve( Map< String, Object > claims ) {
                return new Principal( "sub", Principal.Type.USER, List.of( "ROLE_ADMIN" ), Map.of(), "user@example.fr" );
            }


            @Override
            public boolean isClient( Map< String, Object > claims ) {
                return false;
            }


            @Override
            public void evictIdentity( String sub ) {
            }


            @Override
            public void evictClient( String clientId ) {
            }
        };
    }
}
