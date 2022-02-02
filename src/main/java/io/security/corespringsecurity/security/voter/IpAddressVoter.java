package io.security.corespringsecurity.security.voter;

import io.security.corespringsecurity.service.SecurityResourceService;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.WebAuthenticationDetails;

import java.util.Collection;
import java.util.HashMap;


/**
 * 심의기준 :
 * - 특정한 IP 만 접근이 가능하도록 심의하는 Voter
 * - Voter 중에서 가장 먼저 심사하도록 하여 허용된 IP 일 경우에만 최종 승인 및 거부 결정을 하도록 한다.
 * - 허용된 IP 이면 ACCESS_GRANTED 가 아닌 ACCESS_ABSTAIN 을 리턴해서 추가 심의를 계속 진행하도록 한다.
 * - 허용된 IP 가 아니면 ACCESS_DENIED 를 리턴하지 않고 즉시 예외 발생하여 최종 자원 접근을 거부한다.
 */
public class IpAddressVoter implements AccessDecisionVoter<Object> {

    private SecurityResourceService securityResourceService;

    public IpAddressVoter(SecurityResourceService securityResourceService) {
        this.securityResourceService = securityResourceService;
    }

    @Override
    public boolean supports(ConfigAttribute attribute) {
        return true;
    }

    @Override
    public boolean supports(Class<?> clazz) {
        return true;
    }

    /**
     * @param authentication - 인증정보(사용자의 정보)
     * @param object         - request 정보
     * @param attributes     - 자원에 접근할때 필요한 권한 정보를 얻을 수 있다.
     * @return
     */
    @Override
    public int vote(Authentication authentication, Object object, Collection<ConfigAttribute> attributes) {
        //사용자의 ip 주소를 얻을 수 있다.
        WebAuthenticationDetails details = (WebAuthenticationDetails) authentication.getDetails();
        String remoteAddress = details.getRemoteAddress();

        HashMap<String, String> accessIpList = securityResourceService.getAccessIpList();

        int result = ACCESS_DENIED;

        //해당 구문은 forEach 를 수행하는데, Map 형식이면 O(1) 으로 줄일 수 있을듯 하다.
//        for (String s : accessIpList) {
//            if (remoteAddress.equals(s)) {
//                return ACCESS_ABSTAIN;
//            }
//        }

        if (accessIpList.get(remoteAddress) != null) {
            return ACCESS_ABSTAIN;
        }

        if (result == ACCESS_DENIED) {
            throw new AccessDeniedException("Invalid IpAddress");
        }

        return result;
    }
}
