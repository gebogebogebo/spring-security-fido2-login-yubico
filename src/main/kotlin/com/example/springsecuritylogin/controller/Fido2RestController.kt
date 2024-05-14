package com.example.springsecuritylogin.controller

import com.example.springsecuritylogin.service.FidoCredentialService
import com.example.springsecuritylogin.service.RegisterOption
import com.example.springsecuritylogin.service.Status
import com.example.springsecuritylogin.service.WebauthnServerService
import com.example.springsecuritylogin.util.SecurityContextUtil
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RestController
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpSession


@RestController
class Fido2RestController(
    private val webauthnServerService: WebauthnServerService,
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
            val registerOption = webauthnServerService.getRegisterOption(user.username)
            session.setAttribute("registerOption", registerOption)

            return ServerPublicKeyCredentialCreationOptionsResponse(registerOption)
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

        val registerOption = session.getAttribute("registerOption") as? RegisterOption
            ?: return ServerResponse(Status.FAILED, "registerOption not found")

        val user = SecurityContextUtil.getLoginUser() ?: return ServerPublicKeyCredentialCreationOptionsResponse(
            Status.FAILED,
            "user not found"
        )

        return try {
            val attestationVerifyResult = webauthnServerService.verifyRegisterAttestation(
                registerOption,
                publicKeyCredentialCreateResult.toAttestation(),
            )

            fidoCredentialService.save(user.username, attestationVerifyResult)

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
            val authenticateOption = webauthnServerService.getAuthenticateOption()
            session.setAttribute("authenticateOption", authenticateOption)

            return ServerPublicKeyCredentialGetOptionsResponse(authenticateOption)
        } catch (e: Exception) {
            ServerPublicKeyCredentialGetOptionsResponse(Status.FAILED, e.message ?: "")
        }
    }
}
