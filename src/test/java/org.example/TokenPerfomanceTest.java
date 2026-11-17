package org.example;

import org.example.security.JwtService;
import org.example.security.OpaqueTokenService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class TokenPerformanceTest {

    @Autowired
    private JwtService jwtService;

    @Autowired
    private OpaqueTokenService opaqueTokenService;

    private static final int N = 10_000;

    private static final String USER = "perf@test.local";
    private static final long ACCESS_TTL_MS = 900_000L;

    @Test
    void compareJwtVsOpaque() {
        warmUp();

        long jwtStart = System.nanoTime();
        for (int i = 0; i < N; i++) {
            String token = jwtService.generateAccessToken(USER);
            boolean ok = jwtService.isAccessTokenValid(token, USER);
            assertThat(ok).isTrue();
        }
        long jwtNanos = System.nanoTime() - jwtStart;

        long opaqueStart = System.nanoTime();
        for (int i = 0; i < N; i++) {
            OpaqueTokenService.OpaqueToken token =
                    opaqueTokenService.issue(USER, "access", ACCESS_TTL_MS);
            boolean ok = opaqueTokenService.isValid(token.value(), "access");
            assertThat(ok).isTrue();
        }
        long opaqueNanos = System.nanoTime() - opaqueStart;

        double jwtNsPerOp = (double) jwtNanos / N;
        double opaqueNsPerOp = (double) opaqueNanos / N;

        System.out.printf("JWT    : %,15d ns total | %,10.2f ns/op%n", jwtNanos, jwtNsPerOp);
        System.out.printf("Opaque : %,15d ns total | %,10.2f ns/op%n", opaqueNanos, opaqueNsPerOp);
        System.out.printf("JWT/Opaque ratio: %.2fx%n", jwtNsPerOp / opaqueNsPerOp);

        assertThat(jwtNanos).isPositive();
        assertThat(opaqueNanos).isPositive();
        assertThat(jwtNsPerOp).isGreaterThan(0.0);
        assertThat(opaqueNsPerOp).isGreaterThan(0.0);
    }

    private void warmUp() {
        for (int i = 0; i < 1_000; i++) {
            String j = jwtService.generateAccessToken(USER);
            jwtService.isAccessTokenValid(j, USER);
            OpaqueTokenService.OpaqueToken o =
                    opaqueTokenService.issue(USER, "access", ACCESS_TTL_MS);
            opaqueTokenService.isValid(o.value(), "access");
        }
        opaqueTokenService.clear();
    }
}