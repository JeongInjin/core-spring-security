package io.security.corespringsecurity.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.security.corespringsecurity.domain.dto.AccountDto;
import io.security.corespringsecurity.security.token.AjaxAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

//ajax 방식으로 로그인 요청 json 방식으로 통신
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login"));
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        //ajax 인지 확인용 서로간의 약속
        if (!isAjax(request)) {
            throw new IllegalStateException("Authentication is not supported");
        }

        //objectMapper 를 이용한 json 으로 넘어온 header 값 AccountDto로 파싱
        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);

        //StringUtils.isEmpty 는 권장하는 방법이 아니여서 hasLength, hasText 로 해봄.
        if (!StringUtils.hasLength(accountDto.getUsername()) || !StringUtils.hasText(accountDto.getPassword())) {
            throw new IllegalArgumentException("Username or Password is empty");
        }
        //AjaxAuthenticationToken 첫번째 생성자 호출
        AjaxAuthenticationToken authenticationToken = new AjaxAuthenticationToken(accountDto.getUsername(), accountDto.getPassword());

        //인증처리를 하게되는 getAuthenticationManager 에게 전달한다.
        return getAuthenticationManager().authenticate(authenticationToken);
    }

    private boolean isAjax(HttpServletRequest request) {
        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return true;
        }

        return false;
    }
}
