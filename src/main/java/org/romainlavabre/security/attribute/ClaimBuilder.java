package org.romainlavabre.security.attribute;

import org.romainlavabre.security.User;

public interface ClaimBuilder {
    String name();


    Object value( User user );
}
