package org.romainlavabre.security.session;

import org.romainlavabre.request.Request;

import java.util.List;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface Logout {

    List< String > logout( Request request );
}
