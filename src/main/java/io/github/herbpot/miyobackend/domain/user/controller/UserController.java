package io.github.herbpot.miyobackend.domain.user.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
@RequiredArgsConstructor
@RequestMapping("/password")
public class UserController {
    @GetMapping("/reset")
    public String showPasswordResetPage(@RequestParam String token, Model model) {
        model.addAttribute("token", token);
        return "reset-password"; // src/main/resources/templates/reset-password.html 파일을 렌더링
    }
}
