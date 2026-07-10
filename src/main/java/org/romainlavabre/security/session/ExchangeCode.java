package org.romainlavabre.security.session;

import org.romainlavabre.request.Request;

import java.util.List;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface ExchangeCode {

    ExchangeResult exchange( Request request );


    class ExchangeResult {
        protected final List< String > cookies;

        protected final long exp;


        public ExchangeResult( List< String > cookies, long exp ) {
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
