package io.security.corespringsecurity.config;

import io.security.corespringsecurity.repository.ResourcesRepository;
<<<<<<< HEAD
import io.security.corespringsecurity.service.SecurityResourceService;
=======
import io.security.corespringsecurity.security.service.SecurityResourceService;
>>>>>>> e32bbfe (웹기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource(2) test 완료)
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {

    @Bean
    public SecurityResourceService securityResourceService(ResourcesRepository resourcesRepository) {
        SecurityResourceService securityResourceService = new SecurityResourceService(resourcesRepository);
<<<<<<< HEAD
        
=======

>>>>>>> e32bbfe (웹기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource(2) test 완료)
        return securityResourceService;
    }
}
