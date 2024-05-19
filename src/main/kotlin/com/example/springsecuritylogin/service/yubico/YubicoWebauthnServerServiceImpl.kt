package com.example.springsecuritylogin.service.yubico

import com.example.springsecuritylogin.repository.MuserRepository
import com.example.springsecuritylogin.service.AssertionVerifyResult
import com.example.springsecuritylogin.service.AttestationVerifyResult
import com.example.springsecuritylogin.service.AuthenticateOption
import com.example.springsecuritylogin.service.RegisterOption
import com.example.springsecuritylogin.service.WebauthnServerService
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.FinishAssertionOptions
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.StartAssertionOptions
import com.yubico.webauthn.StartRegistrationOptions
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.ResidentKeyRequirement
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.UserVerificationRequirement
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets

@Service
class YubicoWebauthnServerServiceImpl(
    private val mUserRepository: MuserRepository,
    credentialRepository: CredentialRepository,
) : WebauthnServerService {
    private val rpId = RelyingPartyIdentity.builder()
        .id("localhost")
        .name("yubico-webauthn-server-test")
        .build()

    private val rp = RelyingParty.builder()
        .identity(rpId)
        .credentialRepository(credentialRepository)
        .origins(setOf("http://localhost:8080"))
//                .attestationConveyancePreference(AttestationConveyancePreference.NONE)
//                .allowUntrustedAttestation(true)
//                .validateSignatureCounter(false)
        .build()

    override fun getRegisterOption(userId: String): RegisterOption {
        val mUser = mUserRepository.findByUserId(userId) ?: throw RuntimeException("User not found")

        val user = UserIdentity.builder()
            .name(mUser.userId)
            .displayName(mUser.displayName)
            .id(createUserId(mUser.internalId))
            .build()

        val authenticatorSelectionCriteria = AuthenticatorSelectionCriteria.builder()
            .residentKey(ResidentKeyRequirement.REQUIRED)
            .userVerification(UserVerificationRequirement.REQUIRED)
//            .authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
            .build()

        val startRegistrationOptions = StartRegistrationOptions.builder()
            .user(user)
            .authenticatorSelection(authenticatorSelectionCriteria)
            .timeout(60000)
            .build()

        return RegisterOption(rp.startRegistration(startRegistrationOptions))
    }

    override fun verifyRegisterAttestation(
        registerOption: RegisterOption,
        publicKeyCredentialCreateResultJson: String,
    ): AttestationVerifyResult {
        val pkc = PublicKeyCredential.parseRegistrationResponseJson(publicKeyCredentialCreateResultJson)

        val finishRegistrationOptions = FinishRegistrationOptions.builder()
            .request(registerOption.publicKeyCredentialCreationOptions)
            .response(pkc)
            .build()

        val result = rp.finishRegistration(finishRegistrationOptions)

        return AttestationVerifyResult(
            credentialId = result.keyId.id.bytes,
            signCount = pkc.response.attestation.authenticatorData.signatureCounter,
            credentialPublicKey = result.publicKeyCose.bytes,
        )
    }

    override fun getAuthenticateOption(): AuthenticateOption {
        val startAssertionOptions = StartAssertionOptions.builder()
            .username(null)
            .userVerification(UserVerificationRequirement.REQUIRED)
            .timeout(120000)
            .build()

        return AuthenticateOption(rp.startAssertion(startAssertionOptions))
    }

    override fun verifyAuthenticateAssertion(
        authenticateOption: AuthenticateOption,
        publicKeyCredentialGetResultJson: String,
    ): AssertionVerifyResult {

        val pkc = PublicKeyCredential.parseAssertionResponseJson(publicKeyCredentialGetResultJson)

        val finishAssertionOptions = FinishAssertionOptions.builder()
            .request(authenticateOption.assertionRequest)
            .response(pkc)
            .build()

        val result = rp.finishAssertion(finishAssertionOptions)

        return AssertionVerifyResult(result.isSuccess, result.username)
    }


    private fun createUserId(userId: String): ByteArray {
        return ByteArray(userId.toByteArray(StandardCharsets.UTF_8))
    }

}
