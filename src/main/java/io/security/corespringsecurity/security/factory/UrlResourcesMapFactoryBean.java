package io.security.corespringsecurity.security.factory;

<<<<<<< HEAD
import io.security.corespringsecurity.service.SecurityResourceService;
=======
import io.security.corespringsecurity.security.service.SecurityResourceService;
>>>>>>> e32bbfe (웹기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource(2) test 완료)
import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import java.util.LinkedHashMap;
import java.util.List;

public class UrlResourcesMapFactoryBean implements FactoryBean<LinkedHashMap<RequestMatcher, List<ConfigAttribute>>> {

    private SecurityResourceService securityResourceService;
    private LinkedHashMap<RequestMatcher, List<ConfigAttribute>> resourceMap;

    public void setSecurityResourceService(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getObject() throws Exception {

        if (resourceMap == null) {
            init();
        }
<<<<<<< HEAD
=======

>>>>>>> e32bbfe (웹기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource(2) test 완료)
        return resourceMap;
    }

    private void init() {
        resourceMap = securityResourceService.getResourceList();
    }

    @Override
    public Class<?> getObjectType() {
        return LinkedHashMap.class;
    }

    @Override
    public boolean isSingleton() {
<<<<<<< HEAD
        return true;
=======
        return FactoryBean.super.isSingleton();
>>>>>>> e32bbfe (웹기반 인가처리 DB 연동 - FilterInvocationSecurityMetadataSource(2) test 완료)
    }
}
