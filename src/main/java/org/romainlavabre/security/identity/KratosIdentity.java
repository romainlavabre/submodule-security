package org.romainlavabre.security.identity;

import java.util.Map;

/**
 * An identity as the Kratos admin API describes it.
 *
 * @param id            The Kratos id, which is the sub of its tokens
 * @param email         traits.email, the login identifier
 * @param state         active or inactive
 * @param metadataAdmin Data only the admin API reads and writes, never exposed to the identity itself.
 *                      Empty, never null.
 * @param createdAt     ISO 8601
 * @param updatedAt     ISO 8601
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public record KratosIdentity(
        String id,
        String email,
        String state,
        Map< String, Object > metadataAdmin,
        String createdAt,
        String updatedAt
) {
    public static final String STATE_ACTIVE   = "active";
    public static final String STATE_INACTIVE = "inactive";


    public boolean isActive() {
        return STATE_ACTIVE.equals( state );
    }
}
