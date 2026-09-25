package org.romainlavabre.security.session;

import java.util.Map;

/**
 * Reads the payload of a JWT minted by the Kratos tokenizer, without checking its signature.
 * <p>
 * Only meant for a token just obtained from Kratos over the internal network, which is therefore already
 * trusted. An incoming token must go through the JwtDecoder instead.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface JwtReader {

    Map< String, Object > getBody( String token );
}
