package io.github.herbpot.miyobackend.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Write DataSource Repository Configuration
 * - PostRepository (posts_write 테이블)
 */
@Configuration
@EnableJpaRepositories(
        basePackages = "io.github.herbpot.miyobackend.domain.community.repository.write",
        entityManagerFactoryRef = "writeEntityManagerFactory",
        transactionManagerRef = "writeTransactionManager"
)
public class WriteDataSourceConfig {
}
