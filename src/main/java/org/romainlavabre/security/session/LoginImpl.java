package org.romainlavabre.security.session;

import org.romainlavabre.dataconverter.Cast;
import org.romainlavabre.exception.HttpBadRequestException;
import org.romainlavabre.exception.HttpInternalServerErrorException;
import org.romainlavabre.request.Request;
import org.romainlavabre.rest.Response;
import org.romainlavabre.rest.Rest;
import org.romainlavabre.security.config.SecurityConfigurer;
import org.romainlavabre.security.message.Error;
import org.romainlavabre.security.parameter.AuthParameter;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

/**
 * Kratos login by email code, driven server side against the Kratos public API (native API flow).
 * The browser never talks to Kratos.
 * <p>
 * IMPORTANT: an API flow carrying a Cookie header is silently rejected by Kratos (anti-CSRF), so these
 * calls never forward the browser's cookies (Rest opens fresh connections).
 *
 * @author Romain Lavabre <romain.lavabre@proton.me>
 */
@Service
public class LoginImpl implements Login {

    protected final JwtReader     jwtReader;
    protected final CookieBuilder cookieBuilder;
    protected final OtpThrottle   otpThrottle;


    public LoginImpl( JwtReader jwtReader, CookieBuilder cookieBuilder, OtpThrottle otpThrottle ) {
        this.jwtReader     = jwtReader;
        this.cookieBuilder = cookieBuilder;
        this.otpThrottle   = otpThrottle;
    }


    /**
     * Answers the same whether the identifier exists or not, and whether it is throttled or not:
     * anything else would let a caller enumerate the accounts.
     */
    @Override
    public InitResult init( Request request ) {
        String identifier = request.getParameter( AuthParameter.IDENTIFIER, String.class );

        if ( identifier == null || identifier.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_IDENTIFIER_REQUIRED, false );
        }

        // Throttled: answer exactly like a success, with no flow cookie so that an already received
        // code stays verifiable. A 429 here would tell an attacker the identifier exists.
        if ( !otpThrottle.allow( identifier ) ) {
            return new InitResult( List.of() );
        }

        String publicUrl = kratosPublicUrl();

        // 1) Open a login flow (no Cookie header, see class doc).
        Response flowResponse =
                Rest.builder()
                        .get( publicUrl + "/self-service/login/api" )
                        .addHeader( "Accept", "application/json" )
                        .buildAndSend();

        if ( !flowResponse.isSuccess() || flowResponse.getBodyAsMap().get( "id" ) == null ) {
            throw new HttpInternalServerErrorException( Error.IDP_LOGIN_INIT_FAILED, false );
        }

        String flowId = flowResponse.getBodyAsMap().get( "id" ).toString();

        // 2) Ask Kratos to email the code. It answers 400 with the flow enriched with the "code" field
        // it now expects: that is the NORMAL response, not an error. An unknown identifier answers
        // the same, which keeps the account enumeration closed.
        Rest.builder()
                .post( publicUrl + "/self-service/login" )
                .queryString( "flow", flowId )
                .jsonBody( Map.of(
                        "method", "code",
                        "identifier", identifier
                ) )
                .buildAndSend();

        return new InitResult( List.of(
                cookieBuilder.kratosFlow( flowId )
        ) );
    }


    /**
     * No attempt counter here on purpose: Kratos burns the code after 5 wrong submissions on a given
     * flow, the 6th being rejected even when it carries the valid code (measured by FairFair on
     * oryd/kratos:v26.2.0).
     * <p>
     * That cap is hardcoded upstream, NOT a kratos.yml setting (there is no max_attempts knob), so it
     * comes with no contractual guarantee: re-check it on every Kratos upgrade, otherwise this
     * endpoint becomes bruteforceable.
     */
    @Override
    public VerifyResult verify( Request request ) {
        String identifier = request.getParameter( AuthParameter.IDENTIFIER, String.class );
        String otp        = request.getParameter( AuthParameter.OTP, String.class );

        if ( identifier == null || identifier.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_IDENTIFIER_REQUIRED, false );
        }

        if ( otp == null || otp.isBlank() ) {
            throw new HttpBadRequestException( Error.IDP_OTP_REQUIRED, false );
        }

        String flowId = SessionCookies.readKratosFlow( request );

        if ( flowId == null ) {
            throw new HttpBadRequestException( Error.IDP_NO_FLOW, false );
        }

        String publicUrl = kratosPublicUrl();

        // Submit the code. 4xx = wrong or expired code, surfaced as a bad request to the front.
        Response submit =
                Rest.builder()
                        .post( publicUrl + "/self-service/login" )
                        .queryString( "flow", flowId )
                        .jsonBody( Map.of(
                                "method", "code",
                                "identifier", identifier,
                                "code", otp
                        ) )
                        .buildAndSend();

        if ( !submit.isSuccess() ) {
            throw new HttpBadRequestException( Error.IDP_INVALID_CODE, false );
        }

        Object sessionToken = submit.getBodyAsMap().get( "session_token" );

        if ( sessionToken == null ) {
            throw new HttpInternalServerErrorException( Error.IDP_LOGIN_FAILED, false );
        }

        // Turn the session into a short-lived signed JWT (tokenizer).
        Response who =
                Rest.builder()
                        .get( publicUrl + "/sessions/whoami" )
                        .queryString( "tokenize_as", kratosTokenizeAs() )
                        .addHeader( "X-Session-Token", sessionToken.toString() )
                        .buildAndSend();

        if ( !who.isSuccess() || who.getBodyAsMap().get( "tokenized" ) == null ) {
            throw new HttpInternalServerErrorException( Error.IDP_LOGIN_FAILED, false );
        }

        String jwt = who.getBodyAsMap().get( "tokenized" ).toString();

        return new VerifyResult(
                List.of(
                        cookieBuilder.accessToken( jwt ),
                        cookieBuilder.refreshToken( sessionToken.toString() ),
                        cookieBuilder.kratosFlow( null )
                ),
                Cast.getLong( jwtReader.getBody( jwt ).get( "exp" ) )
        );
    }


    protected String kratosPublicUrl() {
        String url = SecurityConfigurer.get().getKratosPublicUrl();

        if ( url == null || url.isBlank() ) {
            throw new IllegalStateException( "Kratos public url is required, use SecurityConfigurer.setKratosPublicUrl()" );
        }

        return url;
    }


    protected String kratosTokenizeAs() {
        String tokenizeAs = SecurityConfigurer.get().getKratosTokenizeAs();

        if ( tokenizeAs == null || tokenizeAs.isBlank() ) {
            throw new IllegalStateException( "Kratos tokenizer template is required, use SecurityConfigurer.setKratosTokenizeAs()" );
        }

        return tokenizeAs;
    }
}
