package io.github.herbpot.miyobackend.domain.challenge.controller;


import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/")
public class HealthcheckController {

    @GetMapping("/")
    public ResponseEntity<Void> index() {
        return ResponseEntity.ok().build();
    }
}