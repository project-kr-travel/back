package com.project.travel.domain.auth.service;

import com.project.travel.common.security.JwtTokenProvider;
import com.project.travel.domain.auth.dto.request.AuthReissueRequest;
import com.project.travel.domain.auth.dto.request.AuthSignInRequest;
import com.project.travel.domain.auth.dto.request.AuthSignUpRequest;
import com.project.travel.domain.auth.dto.response.AuthReissueResponse;
import com.project.travel.domain.auth.dto.response.AuthSignInResponse;
import com.project.travel.domain.auth.dto.response.AuthSignUpResponse;
import com.project.travel.domain.auth.repository.AuthRedisRepository;
import com.project.travel.domain.user.entity.User;
import com.project.travel.domain.user.entity.UserRole;
import com.project.travel.domain.user.service.UserService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Optional;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@DisplayName("[api/auth] - 단위 테스트")
@ExtendWith(MockitoExtension.class)
class AuthServiceUnitTest {

    @Mock
    JwtTokenProvider jwtTokenProvider;

    @Mock
    BCryptPasswordEncoder bCryptPasswordEncoder;

    @Mock
    UserService userService;

    @Mock
    AuthRedisRepository authRedisRepository;

    @InjectMocks
    AuthService authService;

    Long userId = 1L;
    String email = "email@email.com";
    String password = "password";
    String nickname = "nickname";
    String name = "name";
    String phone = "phone";
    String encodedPassword = "encodedPassword";
    String accessToken = "accessToken";
    String refreshToken = "refreshToken";

    @Nested
    @DisplayName("[/signup] - 회원가입")
    class SignUpTest {

        @Test
        @DisplayName("성공")
        void signUp() {
            // given
            AuthSignUpRequest request = new AuthSignUpRequest(
                    email,
                    password,
                    nickname,
                    name,
                    phone
            );

            User user = request.toEntity(encodedPassword);

            when(userService.existsByEmail(request.email())).thenReturn(false);
            when(bCryptPasswordEncoder.encode(request.password())).thenReturn(encodedPassword);
            when(userService.save(any(User.class))).thenReturn(user);
            when(jwtTokenProvider.generateAccessToken(String.valueOf(user.getId()), user.getRole().getValue()))
                    .thenReturn(accessToken);
            when(jwtTokenProvider.generateRefreshToken()).thenReturn(refreshToken);

            // when
            AuthSignUpResponse response = authService.signUp(request);

            // then
            assertThat(response.accessToken()).isEqualTo(accessToken);
            assertThat(response.refreshToken()).isEqualTo(refreshToken);

            verify(userService, times(1)).existsByEmail(request.email());
            verify(bCryptPasswordEncoder, times(1)).encode(request.password());
            verify(userService, times(1)).save(any(User.class));
            verify(jwtTokenProvider, times(1))
                    .generateAccessToken(String.valueOf(user.getId()), user.getRole().getValue());
            verify(jwtTokenProvider, times(1)).generateRefreshToken();
            verify(authRedisRepository, times(1))
                    .saveRefreshToken(String.valueOf(user.getId()), refreshToken);
        }
    }

    @Nested
    @DisplayName("[/signin] - 로그인")
    class SignInTest {

        @Test
        @DisplayName("성공")
        void signIn() {
            // given
            AuthSignInRequest request = new AuthSignInRequest(
                    email,
                    password
            );

            User user = User.builder()
                    .email(email)
                    .password(encodedPassword)
                    .role(UserRole.USER)
                    .build();

            when(userService.findByEmail(request.email())).thenReturn(user);
            when(bCryptPasswordEncoder.matches(request.password(), encodedPassword)).thenReturn(true);
            when(jwtTokenProvider.generateAccessToken(String.valueOf(user.getId()), user.getRole().getValue()))
                    .thenReturn(accessToken);
            when(jwtTokenProvider.generateRefreshToken()).thenReturn(refreshToken);

            // when
            AuthSignInResponse response = authService.signIn(request);

            // then
            assertThat(response.accessToken()).isEqualTo(accessToken);
            assertThat(response.refreshToken()).isEqualTo(refreshToken);

            verify(userService, times(1)).findByEmail(email);
            verify(bCryptPasswordEncoder, times(1)).matches(request.password(), encodedPassword);
            verify(jwtTokenProvider, times(1))
                    .generateAccessToken(String.valueOf(user.getId()), user.getRole().getValue());
            verify(jwtTokenProvider, times(1)).generateRefreshToken();
            verify(authRedisRepository, times(1))
                    .saveRefreshToken(String.valueOf(user.getId()), refreshToken);
        }
    }

    @Nested
    @DisplayName("[/reissue] - 재발급")
    class ReissueTest {

        @Test
        @DisplayName("성공")
        void reissue() {
            String newAccessToken = "newAccessToken";
            String newRefreshToken = "newRefreshToken";

            // given
            AuthReissueRequest request = new AuthReissueRequest(
                    refreshToken
            );

            User user = User.builder()
                    .id(userId)
                    .email(email)
                    .password(encodedPassword)
                    .role(UserRole.USER)
                    .build();

            when(authRedisRepository.getUserIdFromRefreshToken(refreshToken))
                    .thenReturn(Optional.of(String.valueOf(userId)));
            when(userService.findById(userId)).thenReturn(user);
            when(jwtTokenProvider.generateAccessToken(String.valueOf(userId), user.getRole().getValue()))
                    .thenReturn(newAccessToken);
            when(jwtTokenProvider.generateRefreshToken()).thenReturn(newRefreshToken);

            // when
            AuthReissueResponse response = authService.reissue(request);

            // then
            assertThat(response.accessToken()).isEqualTo(newAccessToken);
            assertThat(response.refreshToken()).isEqualTo(newRefreshToken);

            verify(authRedisRepository, times(1)).getUserIdFromRefreshToken(refreshToken);
            verify(userService, times(1)).findById(userId);
            verify(authRedisRepository, times(1)).deleteRefreshToken(refreshToken);
            verify(jwtTokenProvider, times(1))
                    .generateAccessToken(String.valueOf(userId), user.getRole().getValue());
            verify(jwtTokenProvider, times(1)).generateRefreshToken();
            verify(authRedisRepository, times(1))
                    .saveRefreshToken(String.valueOf(userId), newRefreshToken);
        }
    }
}