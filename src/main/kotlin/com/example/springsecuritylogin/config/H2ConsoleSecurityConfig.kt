package com.example.springsecuritylogin.config

import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter

@Configuration
@Order(1)
class H2ConsoleSecurityConfig : WebSecurityConfigurerAdapter() {
    override fun configure(http: HttpSecurity) {
        http
            .antMatcher("/h2-console/**")
            .authorizeRequests().anyRequest().permitAll()
            .and()
            .headers().frameOptions().disable()
            .and()
            .csrf().disable()
    }
}