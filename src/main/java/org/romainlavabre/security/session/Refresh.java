package org.romainlavabre.security.session;

import org.romainlavabre.request.Request;

import java.util.List;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public interface Refresh {

    RefreshResult refresh( Request request );


    class RefreshResult {
        protected final List< String > cookies;

        protected final long exp;


        public RefreshResult( List< String > cookies, long exp ) {
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
