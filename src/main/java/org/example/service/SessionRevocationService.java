package org.example.service;

import lombok.RequiredArgsConstructor;
import org.example.entity.SessionStatus;
import org.example.entity.UserSession;
import org.example.repository.UserSessionRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class SessionRevocationService {

    private final UserSessionRepository sessionRepository;
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    public void markRevoked(UserSession session) {
        session.setStatus(SessionStatus.REVOKED);
        sessionRepository.save(session);
    }
}