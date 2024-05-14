package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.AuthenticateOption
import com.example.springsecuritylogin.service.FidoCredentialService
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
    private val mFidoCredentialService: FidoCredentialService,
    private val webauthnServerService: WebauthnServerService,
    private val request: HttpServletRequest?
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        val userName = if (authentication is AssertionAuthenticationToken) {

            val authenticateOption = request?.session?.getAttribute("authenticateOption") as? AuthenticateOption
                ?: throw BadCredentialsException("authenticateOption not found")

            val getResult = authentication.credentials.publicKeyCredentialGetResult
            if (getResult.response == null) {
                throw BadCredentialsException("Invalid Assertion")
            }

            val userInternalId = webauthnServerService.toUserInternalId(getResult.response.userHandle)
//            val (credentialRecord, userId) = mFidoCredentialService.load(userInternalId, getResult.id)
//            if (credentialRecord == null) {
//                throw BadCredentialsException("credential not found")
//            }

            val verifyResult = try {
                webauthnServerService.verifyAuthenticateAssertion(
                    authenticateOption,
                    getResult.toAssertion(),
                )
            } catch (e: Exception) {
                throw BadCredentialsException("Invalid Assertion")
            }
            if (!verifyResult) {
                throw BadCredentialsException("Assertion Verify Failed")
            }

            // TODO
            "userId"
        } else {
            throw BadCredentialsException("Invalid Authentication")
        }

        // set Authenticated
        val authorities = listOf(
            SimpleGrantedAuthority(SecurityContextUtil.Auth.AUTHENTICATED_FIDO.value),
            SimpleGrantedAuthority(SecurityContextUtil.Role.USER.value)
        )

        val authencatedPrincipal = User(userName, "", authorities)

        var result = AssertionAuthenticationToken(authencatedPrincipal, authentication.credentials, authorities)
        result.isAuthenticated = true
        return result
    }

    override fun supports(authentication: Class<*>?): Boolean {
        return AssertionAuthenticationToken::class.java.isAssignableFrom(authentication)
    }
}
