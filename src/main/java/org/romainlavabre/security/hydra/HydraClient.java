package org.romainlavabre.security.hydra;

import java.util.List;
import java.util.Map;

/**
 * A client as the Hydra admin API describes it. Its secret is never part of it: Hydra only keeps a hash.
 *
 * @param clientId  The id Hydra generated, which is the client_id of its tokens
 * @param name      client_name
 * @param scopes    The scopes the client may request
 * @param audiences The audiences the client may request
 * @param metadata  Data the application attaches to the client, never put in its tokens. Empty, never null.
 * @param createdAt ISO 8601
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public record HydraClient(
        String clientId,
        String name,
        List< String > scopes,
        List< String > audiences,
        Map< String, Object > metadata,
        String createdAt
) {
}
