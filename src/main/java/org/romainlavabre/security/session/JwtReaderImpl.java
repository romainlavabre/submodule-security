package org.romainlavabre.security.session;

import org.springframework.stereotype.Service;
import tools.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class JwtReaderImpl implements JwtReader {
    protected static final ObjectMapper MAPPER = new ObjectMapper();


    @Override
    public Map< String, Object > getBody( String token ) {
        String payload = new String( Base64.getUrlDecoder().decode( token.split( "\\." )[ 1 ] ), StandardCharsets.UTF_8 );

        return MAPPER.readValue( payload, Map.class );
    }
}
