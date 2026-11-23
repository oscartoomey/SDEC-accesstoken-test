package com.example.springdummyapp;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimNames;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertThrows;

import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.env.Environment;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;

@Slf4j
@SpringBootTest
class SpringDummyAppApplicationTests {

    @Autowired
    private Environment env;

    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;
    private JWKSource<SecurityContext> keySource;
    private String accessToken;

    @BeforeEach
    void setUp() throws MalformedURLException, URISyntaxException {
        String keySourceUrl = env.getRequiredProperty("jwt.key-source");
        String issuer = env.getRequiredProperty("jwt.issuer");
        accessToken = env.getRequiredProperty("jwt.access-token");

        assertNotNull(keySourceUrl, "jwt.key-source should be set");
        assertFalse(keySourceUrl.isBlank(), "jwt.key-source should not be blank");
        assertNotNull(issuer, "jwt.issuer should be set");
        assertFalse(issuer.isBlank(), "jwt.issuer should not be blank");
        assertNotNull(accessToken, "jwt.access-token should be set");
        assertFalse(accessToken.isBlank(), "jwt.access-token should not be blank");

        jwtProcessor = new DefaultJWTProcessor<>();

        jwtProcessor.setJWSTypeVerifier(
                new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("JWT")));

        keySource = JWKSourceBuilder
                .create(new URI(keySourceUrl).toURL())
                .retrying(true)
                .build();

        JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;

        JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(
                expectedJWSAlg,
                keySource);
        jwtProcessor.setJWSKeySelector(keySelector);

        jwtProcessor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                new JWTClaimsSet.Builder().issuer(issuer).build(),
                new HashSet<>(Arrays.asList(
                        JWTClaimNames.SUBJECT,
                        JWTClaimNames.ISSUED_AT,
                        JWTClaimNames.EXPIRATION_TIME,
                        JWTClaimNames.AUDIENCE))));
    }

    @Test
    void testJwt() {
        try {
            SignedJWT jwt = SignedJWT.parse(accessToken);

            log.info(jwt.getHeader().toJSONObject().toString());
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            log.info(claims.toJSONObject().toString());

            String kid = jwt.getHeader().getKeyID();

            List<JWK> matches = keySource.get(
                    new JWKSelector(new JWKMatcher.Builder().keyID(kid).build()),
                    null);

            assertFalse(matches.isEmpty(), "kid " + kid + " NOT in Entra's JWKS");
            assertNotNull(matches.getFirst().toJSONString());

            log.debug("kid {} found: {}", kid, matches.getFirst().toJSONString());

            log.debug(keySource.toString());
        } catch (ParseException | KeySourceException e) {
            log.error(e.getMessage());
        }
    }

    @Test
    void testJwtWithUnknownKid() {
        String fakeKid = "nonexistent-kid-12345";

        try {
            List<JWK> matches = keySource.get(
                    new JWKSelector(new JWKMatcher.Builder().keyID(fakeKid).build()),
                    null);

            assertTrue(matches.isEmpty(), "Expected no match for unknown kid but found: " + matches);
        } catch (KeySourceException e) {
            log.error(e.getMessage());
        }
    }

    @Test
    void testJwtWithMalformedToken() {
        assertThrows(ParseException.class, () -> SignedJWT.parse("not-a-valid-jwt"));
    }

}
