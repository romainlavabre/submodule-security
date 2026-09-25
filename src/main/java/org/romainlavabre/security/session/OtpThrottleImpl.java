package org.romainlavabre.security.session;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Ticker;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * In memory counter: at most 5 sends per identifier over a window of 15 minutes, opened by the first
 * send.
 * <p>
 * The counter lives in the JVM. It is neither shared between instances nor kept across a restart: with
 * N instances behind a load balancer, an identifier can trigger up to 5 × N emails per window. Declare
 * a @Primary OtpThrottle bean when that bound is not acceptable.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class OtpThrottleImpl implements OtpThrottle {

    protected static final int MAX_SENDS = 5;

    protected static final Duration WINDOW = Duration.ofMinutes( 15 );

    protected static final long MAX_IDENTIFIERS = 100_000;

    protected final Cache< String, AtomicInteger > sends;


    public OtpThrottleImpl() {
        this( Ticker.systemTicker() );
    }


    /**
     * @param ticker Lets a test move the clock forward instead of waiting for the window to elapse
     */
    protected OtpThrottleImpl( Ticker ticker ) {
        this.sends = Caffeine.newBuilder()
                .maximumSize( MAX_IDENTIFIERS )
                .expireAfterWrite( WINDOW )
                .ticker( ticker )
                .build();
    }


    /**
     * The window is opened by the first send only: incrementing the counter is no write for the cache,
     * so it does not push the expiry back.
     */
    @Override
    public boolean allow( String identifier ) {
        return sends.get( hash( identifier ), key -> new AtomicInteger() ).incrementAndGet() <= MAX_SENDS;
    }


    /**
     * The identifier is an email: digesting it keeps this cache from becoming a directory of user
     * addresses. Lowercased first, otherwise a change of case would open a fresh counter.
     */
    protected String hash( String identifier ) {
        try {
            return HexFormat.of().formatHex(
                    MessageDigest
                            .getInstance( "SHA-256" )
                            .digest( identifier.trim().toLowerCase( Locale.ROOT ).getBytes( StandardCharsets.UTF_8 ) )
            );
        } catch ( NoSuchAlgorithmException e ) {
            throw new IllegalStateException( e );
        }
    }
}
