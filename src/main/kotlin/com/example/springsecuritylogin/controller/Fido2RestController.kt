package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.Attestation
import com.example.springsecuritylogin.service.FidoCredentialService
import com.example.springsecuritylogin.service.Status
import com.example.springsecuritylogin.service.WebAuthn4JServerService
import com.example.springsecuritylogin.service.YubicoWebauthnServerService
import com.example.springsecuritylogin.util.SecurityContextUtil
import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpSession


@RestController
class Fido2RestController(
    private val webAuthn4JServerService: WebAuthn4JServerService,
    private val yubicoWebauthnServerService: YubicoWebauthnServerService,
    private val fidoCredentialService: FidoCredentialService,
) {
    @PostMapping("/register/option")
    fun registerOption(
        session: HttpSession
    ): ServerPublicKeyCredentialCreationOptionsResponse {
        val user = SecurityContextUtil.getLoginUser() ?: return ServerPublicKeyCredentialCreationOptionsResponse(
            Status.FAILED,
            "user not found"
        )

        return try {

            val serverResponse = yubicoWebauthnServerService.getRegisterOption(user.username)
            session.setAttribute("challenge", serverResponse.challenge.base64Url)
            session.setAttribute("publicKeyCredentialCreationOptions", serverResponse)

            return ServerPublicKeyCredentialCreationOptionsResponse(serverResponse)
        } catch (e: Exception) {
            ServerPublicKeyCredentialCreationOptionsResponse(Status.FAILED, e.message ?: "")
        }
    }

    @PostMapping("/register/verify")
    fun registerVerify(
        @RequestBody publicKeyCredentialCreateResult: PublicKeyCredentialCreateResult,
        httpServletRequest: HttpServletRequest,
        session: HttpSession
    ): ServerResponse {
        if (publicKeyCredentialCreateResult.response == null) return ServerResponse(Status.FAILED, "response not found")

        val challenge = session.getAttribute("challenge") as? String
            ?: return ServerResponse(Status.FAILED, "challenge not found")

        val publicKeyCredentialCreationOptions = session.getAttribute("publicKeyCredentialCreationOptions") as? PublicKeyCredentialCreationOptions
            ?: return ServerResponse(Status.FAILED, "publicKeyCredentialCreationOptions not found")

        val user = SecurityContextUtil.getLoginUser() ?: return ServerPublicKeyCredentialCreationOptionsResponse(
            Status.FAILED,
            "user not found"
        )

        // TODO
        val mapper = jacksonObjectMapper()
        val publicKeyCredentialJson = mapper.writeValueAsString(publicKeyCredentialCreateResult)

        return try {
            yubicoWebauthnServerService.verifyRegisterAttestation(
                challenge,
                publicKeyCredentialCreationOptions,
                Attestation(
                    publicKeyCredentialCreateResult.response.attestationObject,
                    publicKeyCredentialCreateResult.response.clientDataJSON,
                ),
                publicKeyCredentialJson
            )

            val (credentialId, credentialRecord) = webAuthn4JServerService.verifyRegisterAttestation(
                challenge,
                Attestation(
                    publicKeyCredentialCreateResult.response.attestationObject,
                    publicKeyCredentialCreateResult.response.clientDataJSON,
                )
            )

            fidoCredentialService.save(user.username, credentialId, credentialRecord)

            ServerResponse(Status.OK, "")
        } catch (e: Exception) {
            ServerResponse(Status.FAILED, e.message ?: "")
        }
    }

    @PostMapping("/authenticate/option")
    fun authenticateOption(
        session: HttpSession
    ): ServerPublicKeyCredentialGetOptionsResponse {
        return try {
            val assertionRequest = yubicoWebauthnServerService.getAuthenticateOption()

            session.setAttribute("challenge", assertionRequest.publicKeyCredentialRequestOptions.challenge.base64Url)
            session.setAttribute("assertionRequest", assertionRequest)

            return ServerPublicKeyCredentialGetOptionsResponse(assertionRequest.publicKeyCredentialRequestOptions)
        } catch (e: Exception) {
            ServerPublicKeyCredentialGetOptionsResponse(Status.FAILED, e.message ?: "")
        }
    }
}
