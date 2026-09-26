package org.romainlavabre.security.ory;

import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Stands for a Kratos or Hydra admin API: answers every call with the next prepared response, and
 * records what it received.
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
public class FakeOryServer {
    private final HttpServer       server;
    private final List< Recorded > received  = new ArrayList<>();
    private final List< Prepared > responses = new ArrayList<>();


    public FakeOryServer() throws IOException {
        server = HttpServer.create( new InetSocketAddress( "127.0.0.1", 0 ), 0 );
        server.createContext( "/", exchange -> {
            String body = new String( exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8 );

            received.add( new Recorded(
                    exchange.getRequestMethod(),
                    exchange.getRequestURI().getPath(),
                    exchange.getRequestURI().getRawQuery(),
                    body
            ) );

            Prepared prepared = responses.isEmpty() ? new Prepared( 204, "", null ) : responses.remove( 0 );

            if ( prepared.link() != null ) {
                exchange.getResponseHeaders().add( "Link", prepared.link() );
            }

            exchange.getResponseHeaders().add( "Content-Type", "application/json" );

            byte[] bytes = prepared.body().getBytes( StandardCharsets.UTF_8 );

            exchange.sendResponseHeaders( prepared.status(), bytes.length == 0 ? -1 : bytes.length );

            if ( bytes.length > 0 ) {
                try ( OutputStream outputStream = exchange.getResponseBody() ) {
                    outputStream.write( bytes );
                }
            }

            exchange.close();
        } );
        server.start();
    }


    public String url() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }


    public FakeOryServer respond( int status, String body ) {
        return respond( status, body, null );
    }


    public FakeOryServer respond( int status, String body, String link ) {
        responses.add( new Prepared( status, body, link ) );

        return this;
    }


    public Recorded last() {
        return received.get( received.size() - 1 );
    }


    public int count() {
        return received.size();
    }


    public void stop() {
        server.stop( 0 );
    }


    public record Recorded( String method, String path, String query, String body ) {
    }


    private record Prepared( int status, String body, String link ) {
    }
}
