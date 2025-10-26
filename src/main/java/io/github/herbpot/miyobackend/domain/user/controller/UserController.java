package io.github.herbpot.miyobackend.domain.user.controller;

import io.swagger.v3.oas.annotations.Hidden;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Hidden // Swagger UI에서 숨김 (HTML 페이지 렌더링용 MVC 컨트롤러)
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
