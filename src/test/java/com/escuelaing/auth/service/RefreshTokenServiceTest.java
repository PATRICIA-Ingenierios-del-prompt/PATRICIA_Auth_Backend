package com.escuelaing.auth.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.data.redis.core.SetOperations;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.Duration;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class RefreshTokenServiceTest {

    @Mock StringRedisTemplate redisTemplate;
    @Mock ValueOperations<String, String> valueOps;
    @Mock SetOperations<String, String> setOps;

    RefreshTokenService refreshTokenService;
    String userId = UUID.randomUUID().toString();

    @BeforeEach
    void setUp() {
        when(redisTemplate.opsForValue()).thenReturn(valueOps);
        when(redisTemplate.opsForSet()).thenReturn(setOps);
        refreshTokenService = new RefreshTokenService(redisTemplate);
        ReflectionTestUtils.setField(refreshTokenService, "expirationDays", 7L);
    }

    @Test
    void create_storesTokenAndReturnsIt() {
        String token = refreshTokenService.create(userId);

        assertThat(token).isNotBlank();
        verify(valueOps).set(eq("refresh:" + token), eq(userId), eq(Duration.ofDays(7)));
        verify(setOps).add("user_tokens:" + userId, token);
        verify(redisTemplate).expire("user_tokens:" + userId, Duration.ofDays(7));
    }

    @Test
    void validate_returnsUserId_whenTokenExists() {
        when(valueOps.get("refresh:my-token")).thenReturn(userId);

        String result = refreshTokenService.validate("my-token");

        assertThat(result).isEqualTo(userId);
    }

    @Test
    void validate_returnsNull_whenTokenNotFound() {
        when(valueOps.get("refresh:expired")).thenReturn(null);

        String result = refreshTokenService.validate("expired");

        assertThat(result).isNull();
    }

    @Test
    void invalidateToken_deletesTokenAndRemovesFromSet() {
        refreshTokenService.invalidateToken("my-token", userId);

        verify(redisTemplate).delete("refresh:my-token");
        verify(setOps).remove("user_tokens:" + userId, "my-token");
    }

    @Test
    void rotate_invalidatesOldAndCreatesNew() {
        String newToken = refreshTokenService.rotate("old-token", userId);

        verify(redisTemplate).delete("refresh:old-token");
        verify(setOps).remove("user_tokens:" + userId, "old-token");
        assertThat(newToken).isNotEqualTo("old-token");
        verify(valueOps).set(eq("refresh:" + newToken), eq(userId), any());
    }

    @Test
    void invalidateAllSessions_deletesAllTokensAndUserKey() {
        String t1 = UUID.randomUUID().toString();
        String t2 = UUID.randomUUID().toString();
        when(setOps.members("user_tokens:" + userId)).thenReturn(Set.of(t1, t2));

        long count = refreshTokenService.invalidateAllSessions(userId);

        assertThat(count).isEqualTo(2);
        verify(redisTemplate).delete("refresh:" + t1);
        verify(redisTemplate).delete("refresh:" + t2);
        verify(redisTemplate).delete("user_tokens:" + userId);
    }

    @Test
    void invalidateAllSessions_returnsZero_whenNoTokensExist() {
        when(setOps.members("user_tokens:" + userId)).thenReturn(null);

        long count = refreshTokenService.invalidateAllSessions(userId);

        assertThat(count).isZero();
        verify(redisTemplate).delete("user_tokens:" + userId);
    }

    @Test
    void invalidateAllSessions_returnsZero_whenSetIsEmpty() {
        when(setOps.members("user_tokens:" + userId)).thenReturn(Set.of());

        long count = refreshTokenService.invalidateAllSessions(userId);

        assertThat(count).isZero();
    }
}