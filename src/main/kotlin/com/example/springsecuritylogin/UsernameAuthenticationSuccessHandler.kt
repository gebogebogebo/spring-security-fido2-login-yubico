package com.example.springsecuritylogin

import com.example.springsecuritylogin.util.SecurityContextUtil
import org.springframework.security.core.Authentication
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse

class UsernameAuthenticationSuccessHandler(
    private val nextAuthUrl: String,
    defaultTargetUrl: String
) : SimpleUrlAuthenticationSuccessHandler(defaultTargetUrl) {
    override fun onAuthenticationSuccess(
        request: HttpServletRequest?,
        response: HttpServletResponse?,
        authentication: Authentication
    ) {
        if (SecurityContextUtil.isUsernameAuthenticated()) {
            response?.sendRedirect(nextAuthUrl)
        } else {
            super.onAuthenticationSuccess(request, response, authentication)
        }
    }
}
