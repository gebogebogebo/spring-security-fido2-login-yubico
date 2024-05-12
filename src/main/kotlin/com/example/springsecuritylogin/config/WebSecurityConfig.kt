package com.example.springsecuritylogin.config

import com.example.springsecuritylogin.*
import com.example.springsecuritylogin.service.SampleUserDetailsService
import com.example.springsecuritylogin.util.SecurityContextUtil
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.builders.WebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter


@Configuration
@Order(2)
class WebSecurityConfig : WebSecurityConfigurerAdapter() {

    @Autowired
    private lateinit var usernameAuthenticationProvider: UsernameAuthenticationProvider

    @Autowired
    private lateinit var passwordAuthenticationProvider: PasswordAuthenticationProvider

    @Autowired
    private lateinit var fido2AuthenticationProvider: Fido2AuthenticationProvider

    @Autowired
    private lateinit var userDetailsService: SampleUserDetailsService

    override fun configure(
        auth: AuthenticationManagerBuilder,
    ) {
        // setUserDetailsService
        usernameAuthenticationProvider.setUserDetailsService(userDetailsService)
        passwordAuthenticationProvider.setUserDetailsService(userDetailsService)

        // authenticationProvider
        auth.authenticationProvider(usernameAuthenticationProvider)
        auth.authenticationProvider(passwordAuthenticationProvider)
        auth.authenticationProvider(fido2AuthenticationProvider)
    }

    override fun configure(web: WebSecurity) {
        web.ignoring().antMatchers("/css/**", "/js/**", "/images/**");
    }

    override fun configure(http: HttpSecurity) {
        http
            .authorizeRequests()
            .antMatchers("/login", "/login-fido2", "/authenticate/option").permitAll()
            .antMatchers("/password").hasAnyAuthority(SecurityContextUtil.Auth.AUTHENTICATED_USERNAME.value)
            .anyRequest().hasRole(SecurityContextUtil.Role.USER.name)

        // Security Filter
        http
            .formLogin()
            .loginPage("/login").permitAll()
            .successHandler(UsernameAuthenticationSuccessHandler("/password", "/mypage"))
            .failureUrl("/login?error")

        http
            .addFilterAt(createPasswordAuthenticationFilter(), UsernamePasswordAuthenticationFilter::class.java)
            .addFilterAt(createFido2AuthenticationFilter(), UsernamePasswordAuthenticationFilter::class.java)

        // disable csrf
        http
            .csrf()
            .ignoringAntMatchers(
                "/authenticate/option",
                "/register/option",
                "/register/verify",
                )
    }

    private fun createPasswordAuthenticationFilter(): PasswordAuthenticationFilter {
        return PasswordAuthenticationFilter("/password", "POST").also {
            it.setAuthenticationManager(authenticationManagerBean())
            it.setAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler("/login?error"))
        }
    }

    private fun createFido2AuthenticationFilter(): Fido2AuthenticationFilter {
        return Fido2AuthenticationFilter("/login-fido2", "POST").also {
            it.setAuthenticationManager(authenticationManagerBean())
            it.setAuthenticationFailureHandler(SimpleUrlAuthenticationFailureHandler("/login?error"))
        }
    }
}
