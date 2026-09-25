package org.romainlavabre.security.session;

import com.github.benmanes.caffeine.cache.Ticker;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class OtpThrottleImplTest {

    private static final String IDENTIFIER = "artisan@marea-conseil.fr";

    private AtomicLong      nanos;
    private OtpThrottleImpl otpThrottle;


    @Before
    public void setUp() {
        nanos       = new AtomicLong();
        otpThrottle = new OtpThrottleImpl( ( Ticker ) nanos::get );
    }


    @Test
    public void it_allows_five_sends_then_refuses_the_sixth() {
        for ( int i = 0; i < 5; i++ ) {
            Assert.assertTrue( "send " + ( i + 1 ) + " must be allowed", otpThrottle.allow( IDENTIFIER ) );
        }

        Assert.assertFalse( otpThrottle.allow( IDENTIFIER ) );
    }


    /**
     * Otherwise a change of case would open a fresh counter.
     */
    @Test
    public void it_counts_an_identifier_whatever_its_case_and_its_spaces() {
        for ( int i = 0; i < 5; i++ ) {
            otpThrottle.allow( IDENTIFIER );
        }

        Assert.assertFalse( otpThrottle.allow( "  Artisan@Marea-Conseil.FR " ) );
    }


    @Test
    public void it_counts_each_identifier_apart() {
        for ( int i = 0; i < 5; i++ ) {
            otpThrottle.allow( IDENTIFIER );
        }

        Assert.assertTrue( otpThrottle.allow( "other@marea-conseil.fr" ) );
    }


    @Test
    public void it_allows_again_once_the_window_is_over() {
        for ( int i = 0; i < 6; i++ ) {
            otpThrottle.allow( IDENTIFIER );
        }

        nanos.addAndGet( Duration.ofMinutes( 15 ).plusSeconds( 1 ).toNanos() );

        Assert.assertTrue( otpThrottle.allow( IDENTIFIER ) );
    }


    /**
     * The window is opened by the first send: sending again does not push it back.
     */
    @Test
    public void it_does_not_slide_the_window_on_each_send() {
        otpThrottle.allow( IDENTIFIER );

        nanos.addAndGet( Duration.ofMinutes( 14 ).toNanos() );

        for ( int i = 0; i < 4; i++ ) {
            otpThrottle.allow( IDENTIFIER );
        }

        Assert.assertFalse( otpThrottle.allow( IDENTIFIER ) );

        nanos.addAndGet( Duration.ofMinutes( 2 ).toNanos() );

        Assert.assertTrue( otpThrottle.allow( IDENTIFIER ) );
    }
}
