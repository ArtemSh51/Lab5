package org.example.security;

import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class OpaqueTokenService {

    public record OpaqueToken(String value, String username, String type, Instant expiry) {}

    private final Map<String, OpaqueToken> store = new ConcurrentHashMap<>();

    public OpaqueToken issue(String username, String type, long ttlMillis) {
        String value = UUID.randomUUID().toString().replace("-", "")
                + UUID.randomUUID().toString().replace("-", "");
        OpaqueToken token = new OpaqueToken(
                value, username, type, Instant.now().plusMillis(ttlMillis));
        store.put(value, token);
        return token;
    }

    public boolean isValid(String value, String type) {
        if (value == null || type == null) {
            return false;
        }
        OpaqueToken t = store.get(value);
        return t != null
                && t.type().equals(type)
                && t.expiry().isAfter(Instant.now());
    }

    public OpaqueToken get(String value) {
        return store.get(value);
    }

    public void revoke(String value) {
        if (value != null) {
            store.remove(value);
        }
    }

    public int size() {
        return store.size();
    }

    public void clear() {
        store.clear();
    }
}