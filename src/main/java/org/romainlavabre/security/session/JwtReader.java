package org.romainlavabre.security.session;

import java.util.Map;

/**
 * Reads the payload of a JWT issued by AWS Cognito, without checking its signature.
 * <p>
 * Only meant for a token just obtained from Cognito over TLS, which is therefore already trusted. An incoming
 * token must go through the JwtDecoder instead.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface JwtReader {

    Map< String, Object > getBody( String token );
}
