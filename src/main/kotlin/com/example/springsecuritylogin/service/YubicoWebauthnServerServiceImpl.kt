package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MfidoCredentialRepository
import com.example.springsecuritylogin.repository.MuserRepository
import com.webauthn4j.credential.CredentialRecord
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.FinishAssertionOptions
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.StartAssertionOptions
import com.yubico.webauthn.StartRegistrationOptions
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.ResidentKeyRequirement
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.UserVerificationRequirement
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets

@Service
class YubicoWebauthnServerServiceImpl(
    private val mUserRepository: MuserRepository,
    private val mFidoCredentialRepository: MfidoCredentialRepository,
    private val yubicoWebauthnServerCredentialRepository: YubicoWebauthnServerCredentialRepository,
) : YubicoWebauthnServerService {
    private val rpId = RelyingPartyIdentity.builder()
        .id("localhost")
        .name("yubico-webauthn-server-test")
        .build()

    private val rp = RelyingParty.builder()
        .identity(rpId)
        .credentialRepository(yubicoWebauthnServerCredentialRepository)
        .origins(setOf("http://localhost:8080"))
//                .attestationConveyancePreference(AttestationConveyancePreference.NONE)
//                .allowUntrustedAttestation(true)
//                .validateSignatureCounter(false)
        .build()

    override fun getRegisterOption(userId: String): RegisterOption {
        val mUser = mUserRepository.findById(userId).orElseThrow { RuntimeException("User not found") }

        val user = UserIdentity.builder()
            .name(mUser.id)
            .displayName(mUser.id)
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
        attestation: Attestation,
    ): AttestationVerifyResult {

        val pkc = PublicKeyCredential.parseRegistrationResponseJson(attestation.publicKeyCredentialJson)

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
        /*
        authenticatorData.setSignCount(pkc.getResponse().getAttestation().getAuthenticatorData().getSignatureCounter());
        authenticatorData.setCredentialId(result.getKeyId().getId().getBytes());
        authenticatorData.setCredentialPublicKey(result.getPublicKeyCose().getBytes());
         */
    }

    override fun getAuthenticateOption(): AssertionRequest {
        val startAssertionOptions = StartAssertionOptions.builder()
            .username(null)
            .userVerification(UserVerificationRequirement.REQUIRED)
            .timeout(120000)
            .build()

        return rp.startAssertion(startAssertionOptions)
    }

    override fun verifyAuthenticateAssertion(
        challengeStr: String,
        assertion: Assertion,           // TODO delete
        assertionRequest: AssertionRequest,
        publicKeyCredentialJson: String,
        credentialRecord: CredentialRecord      // TODO delete
    ): Boolean {

        val pkc = PublicKeyCredential.parseAssertionResponseJson(publicKeyCredentialJson)

        val finishAssertionOptions = FinishAssertionOptions.builder()
            .request(assertionRequest)
            .response(pkc)
            .build()

        val result = rp.finishAssertion(finishAssertionOptions)

        return result.isSuccess
    }


    private fun createUserId(userId: String): ByteArray {
        return ByteArray(userId.toByteArray(StandardCharsets.UTF_8))
    }
}
