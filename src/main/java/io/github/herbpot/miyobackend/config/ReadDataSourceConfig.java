package io.github.herbpot.miyobackend.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Read DataSource Repository Configuration
 * - PostReadRepository (posts_read 테이블)
 * - EmpathyRepository (empathy_data 테이블)
 */
@Configuration
@EnableJpaRepositories(
        basePackages = "io.github.herbpot.miyobackend.domain.community.repository.read",
        entityManagerFactoryRef = "readEntityManagerFactory",
        transactionManagerRef = "readTransactionManager"
)
public class ReadDataSourceConfig {
}
