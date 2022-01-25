package io.security.corespringsecurity.security.handler;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 인증 시도를 하다가 발생한 예외는 해당 인증을 처리하고 있는 filter 가 처리하게 되고,
 * 인가 예외같은 경우는 ExceptionTranslationFilter 가 처리하게 된다.
 */
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private String errorPage;

    /**
     * AccessDeniedException 인가 예외 exception
     */
    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();
        response.sendRedirect(deniedUrl);
    }

    public void setErrorPage(String errorPage) {
        this.errorPage = errorPage;
    }
}
