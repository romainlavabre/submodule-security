package org.romainlavabre.security.session;

/**
 * Caps how many code emails a single identifier can trigger. The login endpoint is public and opens a
 * fresh Kratos flow on every call, so Kratos' own per-flow resend guard never applies: without this,
 * one request means one email, indefinitely.
 * <p>
 * The application may declare its own @Primary bean to replace the default one, eg to share the
 * counter between several instances.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface OtpThrottle {

    /**
     * Records the send and returns true when it is allowed. A refusal must stay indistinguishable from
     * a success on the wire: answering differently would reopen account enumeration.
     */
    boolean allow( String identifier );
}
