package org.romainlavabre.security.session;

import org.romainlavabre.request.Request;

import java.util.List;

/**
 * Kratos login, by a one time code sent by email. Two steps because the code is sent then verified:
 * {@link #init(Request)} opens the flow and triggers the email, {@link #verify(Request)} submits the
 * received code and turns the resulting Kratos session into cookies.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface Login {

    /**
     * Opens a Kratos login flow and asks Kratos to send the code by email. Returns the cookie holding
     * the flow id, to be replayed on {@link #verify(Request)}.
     */
    InitResult init( Request request );


    /**
     * Submits the code: on success the Kratos session token becomes the REFRESH_TOKEN cookie and a
     * short-lived tokenized JWT the ACCESS_TOKEN cookie.
     */
    VerifyResult verify( Request request );


    class InitResult {
        protected final List< String > cookies;


        public InitResult( List< String > cookies ) {
            this.cookies = cookies;
        }


        public List< String > getCookies() {
            return cookies;
        }
    }


    class VerifyResult {
        protected final List< String > cookies;

        protected final long exp;


        public VerifyResult( List< String > cookies, long exp ) {
            this.cookies = cookies;
            this.exp     = exp;
        }


        public List< String > getCookies() {
            return cookies;
        }


        public long getExp() {
            return exp;
        }
    }
}
