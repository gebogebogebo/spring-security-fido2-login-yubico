package com.example.springsecuritylogin

import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.util.matcher.AntPathRequestMatcher

class PasswordAuthenticationFilter(
    pattern: String,
    httpMethod: String,
) : UsernamePasswordAuthenticationFilter() {
    init {
        setRequiresAuthenticationRequestMatcher(AntPathRequestMatcher(pattern, httpMethod))
    }
}
