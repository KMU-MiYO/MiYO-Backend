package io.github.herbpot.miyobackend.domain.user.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.herbpot.miyobackend.domain.user.dto.request.LoginRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.SignUpRequest;
import io.github.herbpot.miyobackend.domain.user.dto.request.UpdateUserRequest;
import io.github.herbpot.miyobackend.domain.user.dto.response.TokenResponse;
import io.github.herbpot.miyobackend.domain.user.entity.User;
import io.github.herbpot.miyobackend.domain.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@Transactional
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private SignUpRequest signUpRequest;

    @BeforeEach
    void setUp() {
        signUpRequest = new SignUpRequest();
        signUpRequest.setUserId("testuser");
        signUpRequest.setPassword("password123");
        signUpRequest.setNickname("Test Nickname");
        signUpRequest.setEmail("test@example.com");
        signUpRequest.setProfilePicture("profile.jpg");
    }

    @Test
    @DisplayName("회원가입 - 성공")
    void signUp_Success() throws Exception {
        mockMvc.perform(post("/users/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(signUpRequest)))
                .andExpect(status().isOk());

        User user = userRepository.findByUserId("testuser").orElseThrow();
        assertThat(user.getNickname()).isEqualTo("Test Nickname");
        assertThat(passwordEncoder.matches("password123", user.getPassword())).isTrue();
    }

    @Test
    @DisplayName("로그인 - 성공")
    void login_Success() throws Exception {
        // Given
        mockMvc.perform(post("/users/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)));

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUserId("testuser");
        loginRequest.setPassword("password123");

        // When & Then
        mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accessToken").exists());
    }

    @Test
    @DisplayName("사용자 정보 조회 - 성공")
    void getUserInfo_Success() throws Exception {
        // Given
        mockMvc.perform(post("/users/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)));

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUserId("testuser");
        loginRequest.setPassword("password123");
        MvcResult loginResult = mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andReturn();
        String token = objectMapper.readValue(loginResult.getResponse().getContentAsString(), TokenResponse.class).getAccessToken();

        // When & Then
        mockMvc.perform(get("/users/testuser")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.userId").value("testuser"))
                .andExpect(jsonPath("$.nickname").value("Test Nickname"));
    }

    @Test
    @DisplayName("사용자 정보 수정 - 성공")
    void updateUser_Success() throws Exception {
        // Given
        mockMvc.perform(post("/users/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)));

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUserId("testuser");
        loginRequest.setPassword("password123");
        MvcResult loginResult = mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andReturn();
        String token = objectMapper.readValue(loginResult.getResponse().getContentAsString(), TokenResponse.class).getAccessToken();

        UpdateUserRequest updateUserRequest = new UpdateUserRequest();
        updateUserRequest.setNickname("New Nickname");

        // When & Then
        mockMvc.perform(patch("/users/testuser")
                        .header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(updateUserRequest)))
                .andExpect(status().isOk());

        User user = userRepository.findByUserId("testuser").orElseThrow();
        assertThat(user.getNickname()).isEqualTo("New Nickname");
    }

    @Test
    @DisplayName("사용자 삭제 - 성공")
    void deleteUser_Success() throws Exception {
        // Given
        mockMvc.perform(post("/users/signup")
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(signUpRequest)));

        LoginRequest loginRequest = new LoginRequest();
        loginRequest.setUserId("testuser");
        loginRequest.setPassword("password123");
        MvcResult loginResult = mockMvc.perform(post("/users/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andReturn();
        String token = objectMapper.readValue(loginResult.getResponse().getContentAsString(), TokenResponse.class).getAccessToken();

        // When & Then
        mockMvc.perform(delete("/users/testuser")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk());

        assertThat(userRepository.findByUserId("testuser")).isEmpty();
    }
}
