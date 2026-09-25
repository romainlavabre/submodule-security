package org.romainlavabre.security.identity;

import org.romainlavabre.security.config.SecurityConfigurer;

/**
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
final class KratosAdmin {

    static String url() {
        String url = SecurityConfigurer.get().getKratosAdminUrl();

        if ( url == null || url.isBlank() ) {
            throw new IllegalStateException( "Kratos admin url is required, use SecurityConfigurer.setKratosAdminUrl()" );
        }

        return url;
    }


    private KratosAdmin() {
    }
}
