package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.AuthenticateOption
import com.example.springsecuritylogin.service.WebauthnServerService
import com.example.springsecuritylogin.util.SecurityContextUtil
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.BadCredentialsException
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.stereotype.Component
import javax.servlet.http.HttpServletRequest


@Component
class Fido2AuthenticationProvider(
    private val webauthnServerService: WebauthnServerService,
    private val request: HttpServletRequest?
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        val userName = if (authentication is AssertionAuthenticationToken) {

            val authenticateOption = request?.session?.getAttribute("authenticateOption") as? AuthenticateOption
                ?: throw BadCredentialsException("authenticateOption not found")

            val publicKeyCredentialGetResultJson = authentication.credentials.publicKeyCredentialGetResultJson
            if (publicKeyCredentialGetResultJson.isEmpty()) {
                throw BadCredentialsException("Invalid Assertion")
            }

            val verifyResult = try {
                webauthnServerService.verifyAuthenticateAssertion(
                    authenticateOption,
                    publicKeyCredentialGetResultJson,
                )
            } catch (e: Exception) {
                throw BadCredentialsException("Invalid Assertion")
            }
            if (!verifyResult.isSuccess) {
                throw BadCredentialsException("Assertion Verify Failed")
            }

            verifyResult.userId
        } else {
            throw BadCredentialsException("Invalid Authentication")
        }

        // set Authenticated
        val authorities = listOf(
            SimpleGrantedAuthority(SecurityContextUtil.Auth.AUTHENTICATED_FIDO.value),
            SimpleGrantedAuthority(SecurityContextUtil.Role.USER.value)
        )

        val authenticatedPrincipal = User(userName, "", authorities)

        val result = AssertionAuthenticationToken(authenticatedPrincipal, authentication.credentials, authorities)
        result.isAuthenticated = true
        return result
    }

    override fun supports(authentication: Class<*>): Boolean {
        return AssertionAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}
