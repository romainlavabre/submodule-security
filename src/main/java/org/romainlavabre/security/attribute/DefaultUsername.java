package org.romainlavabre.security.attribute;

import org.romainlavabre.security.User;
import org.springframework.stereotype.Service;

@Service
public class DefaultUsername implements ClaimBuilder {

    @Override
    public String name() {
        return "username";
    }


    @Override
    public Object value( User user ) {
        return user.getUsername();
    }
}
