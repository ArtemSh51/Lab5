package org.example.service;

import lombok.RequiredArgsConstructor;
import org.example.dto.TokenResponse;
import org.example.entity.SessionStatus;
import org.example.entity.User;
import org.example.entity.UserSession;
import org.example.repository.UserSessionRepository;
import org.example.repository.UserRepository;
import org.example.security.JwtService;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtService jwtService;
    private final UserSessionRepository sessionRepository;
    private final UserRepository userRepository;
    private final SessionRevocationService revocationService;

    @Transactional
    public TokenResponse createSession(User user, String deviceId) {
        String accessToken = jwtService.generateAccessToken(user.getEmail());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        UserSession session = new UserSession();
        session.setUsername(user.getEmail());
        session.setDeviceId(deviceId);
        session.setAccessToken(accessToken);
        session.setRefreshToken(refreshToken);
        session.setAccessTokenExpiry(jwtService.extractExpirationInstant(accessToken));
        session.setRefreshTokenExpiry(jwtService.extractExpirationInstant(refreshToken));
        session.setStatus(SessionStatus.ACTIVE);

        sessionRepository.save(session);
        return new TokenResponse(accessToken, refreshToken);
    }

    @Transactional
    public TokenResponse refreshToken(String oldRefreshToken, String deviceId) {
        String username;
        try {
            username = jwtService.extractUsername(oldRefreshToken);
        } catch (Exception e) {
            throw new BadCredentialsException("Неверный или просроченный refresh");
        }
        if (!jwtService.isRefreshTokenValid(oldRefreshToken, username)) {
            throw new BadCredentialsException("Неверный, просроченный или неподходящий по типу refresh");
        }

        UserSession session = sessionRepository.findByRefreshTokenForUpdate(oldRefreshToken)
                .orElseThrow(() -> new BadCredentialsException("Неизвестная refresh-сессия"));

        if (!session.getUsername().equalsIgnoreCase(username)) {
            throw new BadCredentialsException("Refresh не принадлежит сессии");
        }

        if (session.getStatus() == SessionStatus.USED) {
            revocationService.markRevoked(session);
            throw new BadCredentialsException("Refresh уже использован");
        }
        if (session.getStatus() == SessionStatus.REVOKED) {
            throw new BadCredentialsException("Сессия отозвана");
        }

        if (session.getRefreshTokenExpiry().isBefore(Instant.now())) {
            throw new BadCredentialsException("Refresh-токен истек");
        }

        User user = userRepository.findByEmailIgnoreCase(session.getUsername())
                .orElseThrow(() -> new BadCredentialsException("Пользователь не найден"));
        if (!user.isEnabled()) {
            throw new BadCredentialsException("Пользователь заблокирован");
        }

        session.setStatus(SessionStatus.USED);
        sessionRepository.save(session);

        String newAccessToken = jwtService.generateAccessToken(user.getEmail());
        String newRefreshToken = jwtService.generateRefreshToken(user.getEmail());

        UserSession newSession = new UserSession();
        newSession.setUsername(user.getEmail());
        newSession.setDeviceId(deviceId != null ? deviceId : session.getDeviceId());
        newSession.setAccessToken(newAccessToken);
        newSession.setRefreshToken(newRefreshToken);
        newSession.setAccessTokenExpiry(jwtService.extractExpirationInstant(newAccessToken));
        newSession.setRefreshTokenExpiry(jwtService.extractExpirationInstant(newRefreshToken));
        newSession.setStatus(SessionStatus.ACTIVE);

        sessionRepository.save(newSession);
        return new TokenResponse(newAccessToken, newRefreshToken);
    }

    @Transactional
    public void revokeSession(String refreshToken) {
        UserSession session = sessionRepository.findByRefreshToken(refreshToken)
                .orElseThrow(() -> new BadCredentialsException("Сессия не найдена"));
        session.setStatus(SessionStatus.REVOKED);
        sessionRepository.save(session);
    }
}