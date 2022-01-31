package io.security.corespringsecurity.security.filter;

import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * 인증과 인가가 필요없는 자원에 대한 FilterSecurityInterceptor 를 상속받아
 * 부모객체인 AbstractSecurityInterceptor 로 가기전에 null 을 return 하여 처리하려고 만든 class
 * => 뭔가 잘 안되는거같은데, 최초 init 일시에는 되는거같은데 super.AbstractSecurityInterceptor. InterceptorStatusToken 메서드를 계속 타는거같은데..흐음..
 */
public class PermitAllFilter extends FilterSecurityInterceptor {
    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
    private boolean observeOncePerRequest = true;

    private List<RequestMatcher> permitAllRequestMatcher = new ArrayList<>();

    public PermitAllFilter(String... permitAllPattern) {
        createPermitAllPattern(permitAllPattern);
    }

    private void createPermitAllPattern(String... permitAllPattern) {
        for (String pattern : permitAllPattern) {
            permitAllRequestMatcher.add(new AntPathRequestMatcher(pattern));
        }
    }

    @Override
    protected InterceptorStatusToken beforeInvocation(Object object) {

        boolean permitAll = false;
        HttpServletRequest request = ((FilterInvocation) object).getRequest();
        for (RequestMatcher requestMatcher : permitAllRequestMatcher) {
            if (requestMatcher.matches(request)) {
                permitAll = true;
                break;
            }
        }
        if (permitAll) return null;

        return super.beforeInvocation(object);
    }

    public void invoke(FilterInvocation filterInvocation) throws IOException, ServletException {
        if (isApplied(filterInvocation) && this.observeOncePerRequest) {
            // filter already applied to this request and user wants us to observe
            // once-per-request handling, so don't re-do security checking
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
            return;
        }
        // first time this request being called, so perform security checking
        if (filterInvocation.getRequest() != null && this.observeOncePerRequest) {
            filterInvocation.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
        }
        InterceptorStatusToken token = beforeInvocation(filterInvocation);
        try {
            filterInvocation.getChain().doFilter(filterInvocation.getRequest(), filterInvocation.getResponse());
        } finally {
            super.finallyInvocation(token);
        }
        super.afterInvocation(token, null);
    }

    private boolean isApplied(FilterInvocation filterInvocation) {
        return (filterInvocation.getRequest() != null)
                && (filterInvocation.getRequest().getAttribute(FILTER_APPLIED) != null);
    }

}

//public class PermitAllFilter extends FilterSecurityInterceptor {
//    private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";
//
//    private List<RequestMatcher> permitAllRequestMatcher = new ArrayList<>();
//
//    public PermitAllFilter(String... permitAllPattern) {
//        createPermitAllPattern(permitAllPattern);
//    }
//
//    @Override
//    protected InterceptorStatusToken beforeInvocation(Object object) {
//        boolean permitAll = false;
//        HttpServletRequest request = ((FilterInvocation) object).getRequest();
//        for (RequestMatcher requestMatcher : permitAllRequestMatcher) {
//            if (requestMatcher.matches(request)) {
//                permitAll = true;
//                break;
//            }
//        }
//
//        if (permitAll) {
//            return null;
//        }
//
//        return super.beforeInvocation(object);
//    }
//
//    @Override
//    public void invoke(FilterInvocation fi) throws IOException, ServletException {
//
//        if ((fi.getRequest() != null) && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
//                && super.isObserveOncePerRequest()) {
//            // filter already applied to this request and user wants us to observe
//            // once-per-request handling, so don't re-do security checking
//            fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
//        } else {
//            // first time this request being called, so perform security checking
//            if (fi.getRequest() != null) {
//                fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
//            }
//
//            InterceptorStatusToken token = beforeInvocation(fi);
//
//            try {
//                fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
//            } finally {
//                super.finallyInvocation(token);
//            }
//
//            super.afterInvocation(token, null);
//        }
//    }
//
//    private void createPermitAllPattern(String... permitAllPattern) {
//        for (String pattern : permitAllPattern) {
//            permitAllRequestMatcher.add(new AntPathRequestMatcher(pattern));
//        }
//
//    }
//
//}
