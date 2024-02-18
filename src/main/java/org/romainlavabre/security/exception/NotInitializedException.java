package org.romainlavabre.security.exception;

public class NotInitializedException extends RuntimeException {
    public NotInitializedException() {
        super( "Security not initialized, use SecurityConfigurer for fix it" );
    }
}
