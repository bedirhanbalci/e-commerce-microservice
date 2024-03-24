package com.customer.auth.service;

import java.util.UUID;

import org.springframework.stereotype.Service;
import com.customer.auth.model.Token;
import com.customer.auth.model.User;
import com.customer.auth.repository.UserRepository;
import org.apache.commons.codec.digest.DigestUtils;

@Service
public class AuthenticationService {

    private UserRepository userRepository;

    private TokenService tokenService;


    public Token registerUser(String username, String password) {
        if (userRepository.getUserById(username) == null) {
            User user = new User();
            user.setUsername(username);
            String hashedPass = hashPassword(password);
            user.setPassword(hashedPass);
            userRepository.createUser(user);
            return loginUser(username, password);
        }
        return null;
    }

    public Token loginUser(String username, String password) {
        User user = userRepository.getUserById(username);
        if (user.getUsername() != "") {
            String hashedPass = hashPassword(password);
            if (hashedPass.equals(user.getPassword())) {
                String token = generateToken();
                String refToken = generateToken();
                tokenService.saveToken(token, username);
                tokenService.saveRefreshToken(refToken, username);
                return new Token(token, refToken, username);
            }
        }
        return null;
    }

    public Token refreshToken(Token oldToken) {
        boolean isValid = tokenService.isRefTokenValid(oldToken.getRefToken());
        if (isValid) {
            String token = generateToken();
            String newRefToken = generateToken();
            Token newToken = new Token(token, newRefToken, oldToken.getUsername());
            tokenService.invalidateRefreshToken(oldToken.getRefToken());
            tokenService.invalidateToken(oldToken.getToken());
            tokenService.saveToken(newToken.getToken(), oldToken.getUsername());
            tokenService.saveRefreshToken(newToken.getRefToken(), oldToken.getUsername());
            return newToken;
        }
        return null;
    }

    private String generateToken() {
        return UUID.randomUUID().toString();
    }

    private String hashPassword(String password) {
        return DigestUtils.sha256Hex(password);
    }

    public boolean verifyToken(String token) {
        return tokenService.getUsernameByToken(token) != null;
    }
}
