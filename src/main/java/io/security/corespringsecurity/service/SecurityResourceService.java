package io.security.corespringsecurity.service;

import io.security.corespringsecurity.domain.entity.AccessIp;
import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.AccessIpRepository;
import io.security.corespringsecurity.repository.ResourcesRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

@Service
public class SecurityResourceService {

    private ResourcesRepository resourcesRepository;

    @Autowired
    private AccessIpRepository accessIpRepository;

    public SecurityResourceService(ResourcesRepository resourcesRepository) {
        this.resourcesRepository = resourcesRepository;
        this.accessIpRepository = accessIpRepository;
    }


    /**
     * @return Url 방식의 인가처리를 위한 return 되는 LinkedHashMap
     */
    public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {

        LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllResources();
        resourcesList.forEach(r -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            r.getRoleSet().forEach(role -> {
                configAttributeList.add(new SecurityConfig(role.getRoleName()));
            });
            result.put(new AntPathRequestMatcher(r.getResourceName()), configAttributeList);
        });

        return result;
    }

    /**
     * @return Method 방식의 인가처리를 위한 return 되는 LinkedHashMap
     */
    public LinkedHashMap<String, List<ConfigAttribute>> getMethodResourceList() {

        LinkedHashMap<String, List<ConfigAttribute>> result = new LinkedHashMap<>();
        List<Resources> resourcesList = resourcesRepository.findAllMethodResources();
        resourcesList.forEach(r -> {
            List<ConfigAttribute> configAttributeList = new ArrayList<>();
            r.getRoleSet().forEach(role -> {
                configAttributeList.add(new SecurityConfig(role.getRoleName()));
            });
            result.put(r.getResourceName(), configAttributeList);
        });

        return result;
    }

    public HashMap<String, String> getAccessIpList() {
        //list
//        List<String> accessIpList = accessIpRepository.findAll().stream().map(accessIp -> accessIp.getIpAddress()).collect(Collectors.toList());

        //hashMap
        HashMap<String, String> accessIpMap = new HashMap<>();
        accessIpMap = (HashMap<String, String>) accessIpRepository.findAll().stream().collect(Collectors.toMap(AccessIp::getIpAddress, AccessIp::getIpAddress));

        return accessIpMap;
    }
}
