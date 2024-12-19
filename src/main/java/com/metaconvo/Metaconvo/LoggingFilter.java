
package com.metaconvo.Metaconvo;

import jakarta.servlet.*;
import jakarta.servlet.FilterConfig;

import java.io.IOException;
import java.util.Enumeration;

public class LoggingFilter implements Filter {
    private FilterConfig filterConfig;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        this.filterConfig = filterConfig;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (filterConfig != null) {
            System.out.println("Filters in the chain:");
            Enumeration<String> filterNames = filterConfig.getInitParameterNames();
            while (filterNames.hasMoreElements()) {
                System.out.println(filterNames.nextElement());
            }
        } else {
            System.out.println("FilterConfig is not initialized.");
        }
        chain.doFilter(request, response);
    }

    @Override
    public void destroy() {
        System.out.println("LoggingFilter destroyed");
    }
}