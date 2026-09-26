package org.romainlavabre.security.ory;

import org.romainlavabre.rest.Response;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;

/**
 * Reads the pagination of the Ory admin listings, carried by the Link header:
 * {@code <http://kratos:4434/admin/identities?page_size=20&page_token=abc>; rel="next", <...>; rel="first"}
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public final class LinkHeader {
    private static final String HEADER     = "Link";
    private static final String REL_NEXT   = "rel=\"next\"";
    private static final String PAGE_TOKEN = "page_token=";


    /**
     * @return The page_token of the next page, null on the last one
     */
    public static String nextPageToken( Response response ) {
        if ( !response.hasHeader( HEADER ) ) {
            return null;
        }

        return nextPageToken( response.getHeader( HEADER ) );
    }


    /**
     * @param header The raw value of the Link header, null accepted
     * @return The page_token of the rel="next" link, null when there is none
     */
    public static String nextPageToken( String header ) {
        if ( header == null || header.isBlank() ) {
            return null;
        }

        for ( String link : header.split( "," ) ) {
            if ( !link.contains( REL_NEXT ) ) {
                continue;
            }

            int start = link.indexOf( '<' );
            int end   = link.indexOf( '>' );

            if ( start < 0 || end < start ) {
                return null;
            }

            return pageToken( link.substring( start + 1, end ) );
        }

        return null;
    }


    private static String pageToken( String url ) {
        int query = url.indexOf( '?' );

        if ( query < 0 ) {
            return null;
        }

        for ( String parameter : url.substring( query + 1 ).split( "&" ) ) {
            if ( parameter.startsWith( PAGE_TOKEN ) ) {
                String token = URLDecoder.decode( parameter.substring( PAGE_TOKEN.length() ), StandardCharsets.UTF_8 );

                return token.isBlank() ? null : token;
            }
        }

        return null;
    }


    private LinkHeader() {
    }
}
