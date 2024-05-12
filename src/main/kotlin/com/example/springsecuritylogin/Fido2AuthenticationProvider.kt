package com.example.springsecuritylogin

import com.example.springsecuritylogin.service.Assertion
import com.example.springsecuritylogin.service.FidoCredentialService
import com.example.springsecuritylogin.service.WebAuthn4JServerService
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
    private val webAuthn4JServerService: WebAuthn4JServerService,
    private val request: HttpServletRequest?
) : AuthenticationProvider {

    override fun authenticate(authentication: Authentication): Authentication {
        val userName = if (authentication is AssertionAuthenticationToken) {
            // verify FIDO assertion
            val challenge = request?.session?.getAttribute("challenge") as? String
                ?: throw BadCredentialsException("challenge not found")

            val getResult = authentication.credentials.publicKeyCredentialGetResult
            if (getResult.response == null) {
                throw BadCredentialsException("Invalid Assertion")
            }

            val userInternalId = webAuthn4JServerService.toUserInternalId(getResult.response.userHandle)
            val (credentialRecord, userId) = mFidoCredentialService.load(userInternalId, getResult.id)
            if (credentialRecord == null) {
                throw BadCredentialsException("credential not found")
            }

            val verifyResult = try {
                webAuthn4JServerService.verifyAuthenticateAssertion(
                    challenge,
                    Assertion(
                        getResult.id,
                        getResult.response.userHandle,
                        getResult.response.authenticatorData,
                        getResult.response.clientDataJSON,
                        getResult.response.signature,
                    ),
                    credentialRecord
                )
            } catch (e: Exception) {
                throw BadCredentialsException("Invalid Assertion")
            }
            if (!verifyResult) {
                throw BadCredentialsException("Assertion Verify Failed")
            }

            userId
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
