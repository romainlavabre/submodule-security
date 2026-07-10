package org.romainlavabre.security.parameter;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface AuthParameter {
    String PREFIX       = "auth_";
    String CLIENT_ID    = PREFIX + "client_id";
    String CODE         = PREFIX + "code";
    String REDIRECT_URI = PREFIX + "redirect_uri";
}
