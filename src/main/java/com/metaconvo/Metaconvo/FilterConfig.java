package com.metaconvo.Metaconvo;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

//@Configuration
public class FilterConfig {

//    @Bean
    public FilterRegistrationBean<CookieToAuthorizationFilter> cookieToAuthorizationFilter() {
        FilterRegistrationBean<CookieToAuthorizationFilter> registrationBean = new FilterRegistrationBean<>();
        registrationBean.setFilter(new CookieToAuthorizationFilter());
        registrationBean.addUrlPatterns("/*"); // Set the URL patterns to filter
        return registrationBean;
    }
}
