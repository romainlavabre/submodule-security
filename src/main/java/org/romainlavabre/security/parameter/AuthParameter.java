package org.romainlavabre.security.parameter;

/**
 * Keys of the {"auth": {...}} payload, flattened by the Request.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface AuthParameter {
    String PREFIX     = "auth_";
    String IDENTIFIER = PREFIX + "identifier";
    String OTP        = PREFIX + "otp";
}
