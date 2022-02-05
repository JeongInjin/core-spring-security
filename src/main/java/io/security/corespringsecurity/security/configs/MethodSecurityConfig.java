package io.security.corespringsecurity.security.configs;


import io.security.corespringsecurity.security.factory.MethodResourcesMapFactoryBean;
import io.security.corespringsecurity.security.interceptor.CustomMethodSecurityInterceptor;
import io.security.corespringsecurity.security.processor.ProtectPointcutPostProcessor;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.intercept.RunAsManager;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true, securedEnabled = true)
@RequiredArgsConstructor
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

    private final SecurityResourceService securityResourceService;

    /**
     * @return Map 기반으로 메소드 인가처리를 할 수 있는 클래스를 리턴한다.
     */
    @Override
    protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
        return mapBasedMethodSecurityMetadataSource();
    }

    @Bean
    public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {
        return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
    }

    @Bean
    public MethodResourcesMapFactoryBean methodResourcesMapFactoryBean() {
        MethodResourcesMapFactoryBean methodResourcesFactoryBean = new MethodResourcesMapFactoryBean();
        methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("method");

        return methodResourcesFactoryBean;
    }

    @Bean
    public MethodResourcesMapFactoryBean pointcutResourcesMapFactoryBean() {
        MethodResourcesMapFactoryBean methodResourcesFactoryBean = new MethodResourcesMapFactoryBean();
        methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
        methodResourcesFactoryBean.setResourceType("pointcut");

        return methodResourcesFactoryBean;
    }

    @Bean
    public ProtectPointcutPostProcessor protectPointcutPostProcessor() {

        ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
        protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());

        return protectPointcutPostProcessor;
    }
    
    @Bean
    public CustomMethodSecurityInterceptor customMethodSecurityInterceptor(MapBasedMethodSecurityMetadataSource methodSecurityMetadataSource) {
        CustomMethodSecurityInterceptor customMethodSecurityInterceptor = new CustomMethodSecurityInterceptor();
        customMethodSecurityInterceptor.setAccessDecisionManager(accessDecisionManager());
        customMethodSecurityInterceptor.setAfterInvocationManager(afterInvocationManager());
        customMethodSecurityInterceptor.setSecurityMetadataSource(methodSecurityMetadataSource);
        RunAsManager runAsManager = runAsManager();
        if (runAsManager != null) {
            customMethodSecurityInterceptor.setRunAsManager(runAsManager);
        }

        return customMethodSecurityInterceptor;
    }

    /**
     * pointcut 표현식을 parse 하여 parse 한 데이터 중 보안이 필요하고 프록시 대상이 될 빈들을 찾아서
     * 클래스, 메소드, 보안 정보를 추출하여 위 MapBasedMethodSecurityMetadataSource 에 전달해야 한다.
     * 해당 클래스를 생성해야 하는데, 그 클래스는 ProtectPointcutPostProcessor 로 BeanPostProcessor 빈 후처리기 이다.
     * ProtectPointcutPostProcessor 는 초기화 이전 단계에서 db로 부터 전달받은 PointcutExpression 의 표현식과 빈을 비교하는 attempMatch 메소드가 있다.
     * 이러한 과정을 통해 pointcut 표현식에 대상이 되는지 검사한다.
     * 대상이 된다면 빈들은 proxy 객체를 생성되는 대상이 될 수 있다. 권한설정된 메서드는 advice 에 등록될 대상이 된다.
     * MethodResourcesMapFactoryBean class > init() >  return resourceMap 데이터를 ProtectPointcutPostProcessor class > setPointcutMap 에 전달 한다.
     * 해당 전달된 객체로 pointcut 표현식이 파싱이 되고, 파싱된 표현식과 전달받은 빈 들에 대해서 서로 매칭 작업을 하면서 매칭이되면(attmptMatch() -> (matches))
     * 정보를 mapBasedMethodSecurityMetadataSource 전달하여 실직적으로 proxy 객체, advice 등록 대상이 되어 인가처리가 이루어 질 수 있도록 한다.
     * Issue :
     * ProtectPointcutPostProcessor 클래스는 final 클래스로써 상속이 불가하며, 접근제한 범위가 default 인 package 여서 new 형식처럼 객체 생성이 불가능 하다.
     * 그리하여, 리플렉션 방식으로 해당 빈을 생성한다.
     *
     * @return pointcut resource
     * @throws Exception
     */
//    @Bean
//    BeanPostProcessor protectPointcutPostProcessor() throws Exception {
//
//        Class<?> clazz = Class.forName("org.springframework.security.config.method.ProtectPointcutPostProcessor");
//        Constructor<?> declaredConstructor = clazz.getDeclaredConstructor(MapBasedMethodSecurityMetadataSource.class);
//        declaredConstructor.setAccessible(true);
//        Object instance = declaredConstructor.newInstance(mapBasedMethodSecurityMetadataSource());
//        Method setPointcutMap = instance.getClass().getMethod("setPointcutMap", Map.class);
//        setPointcutMap.setAccessible(true);
//        setPointcutMap.invoke(instance, pointcutResourcesMapFactoryBean().getObject());
//
//        return (BeanPostProcessor) instance;
//    }


}