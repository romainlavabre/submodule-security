package org.romainlavabre.security.session;

import org.romainlavabre.dataconverter.Cast;
import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpUnauthorizedException;
import org.romainlavabre.request.Request;
import org.romainlavabre.rest.Response;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.message.Error;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Ory issues no refresh token: the Kratos session token, held by the REFRESH_TOKEN cookie, is the
 * durable credential. Refreshing re-mints the short-lived JWT through the tokenizer AND slides the
 * session, so that an active user never expires mid-use.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class RefreshImpl implements Refresh {

    protected final JwtReader     jwtReader;
    protected final CookieBuilder cookieBuilder;


    public RefreshImpl( JwtReader jwtReader, CookieBuilder cookieBuilder ) {
        this.jwtReader     = jwtReader;
        this.cookieBuilder = cookieBuilder;
    }


    @Override
    public RefreshResult refresh( Request request ) {
        String sessionToken = SessionCookies.readSessionToken( request );

        if ( sessionToken == null ) {
            throw new HttpBadRequestException( Error.IDP_NO_ACTIVE_SESSION, false );
        }

        SecurityConfigurer securityConfigurer = SecurityConfigurer.get();

        // Re-mint the JWT. A dead or revoked session answers 401, the front redirects to the login.
        Response who =
                Rest.builder()
                        .get( securityConfigurer.getKratosPublicUrl() + "/sessions/whoami" )
                        .queryString( "tokenize_as", securityConfigurer.getKratosTokenizeAs() )
                        .addHeader( "X-Session-Token", sessionToken )
                        .buildAndSend();

        Map< String, Object > body = who.getBodyAsMap();

        if ( !who.isSuccess() || body.get( "tokenized" ) == null ) {
            throw new HttpUnauthorizedException( Error.IDP_SESSION_EXPIRED, false );
        }

        String jwt = body.get( "tokenized" ).toString();

        // Sliding window: extend the Kratos session (admin API). Best-effort, a failed extend must not
        // prevent handing back the freshly minted JWT.
        if ( body.get( "id" ) != null ) {
            Rest.builder()
                    .patch( securityConfigurer.getKratosAdminUrl() + "/admin/sessions/" + body.get( "id" ) + "/extend" )
                    .buildAndSend();
        }

        return new RefreshResult(
                List.of(
                        cookieBuilder.accessToken( jwt ),
                        cookieBuilder.refreshToken( sessionToken )
                ),
                Cast.getLong( jwtReader.getBody( jwt ).get( "exp" ) )
        );
    }
}
