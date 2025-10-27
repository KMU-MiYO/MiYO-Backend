package io.github.herbpot.miyobackend;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@SpringBootApplication
@EnableScheduling
public class MiYoBackendApplication {

    public static void main(String[] args) {
        SpringApplication.run(MiYoBackendApplication.class, args);
    }

}
