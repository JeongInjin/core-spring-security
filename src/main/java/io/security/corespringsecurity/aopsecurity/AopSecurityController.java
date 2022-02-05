package io.security.corespringsecurity.aopsecurity;

import io.security.corespringsecurity.domain.dto.AccountDto;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * @EnableGlobalMethodSecurity 를 활성화 시키지 않으면 보안적용 된 애노테이션은 작동을 하지 않는다.
 * Security.config 에서 적용을 하자.
 */

@Controller
@RequiredArgsConstructor
public class AopSecurityController {

    private final AopMethodService aopMethodService;

    @GetMapping("/preAuthorize")
    @PreAuthorize("hasRole('ROLE_USER') AND #account.username == principal.username")
//    @PreAuthorize("hasRole('ROLE_USER')")
    public String preAuthorize(AccountDto account, Model model) {

        System.out.println("account.username = " + account.getUsername() + "");
        model.addAttribute("method", "Success @PreAuthorize");

        return "aop/method";
    }

    @GetMapping("/methodSecured")
    public String methodSecured(Model model) {
        aopMethodService.methodSecured();
        model.addAttribute("method", "Success MethodSecured");

        return "aop/method";
    }

}
