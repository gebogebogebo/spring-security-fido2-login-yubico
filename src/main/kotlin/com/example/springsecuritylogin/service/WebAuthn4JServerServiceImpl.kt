package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MfidoCredentialRepository
import com.example.springsecuritylogin.repository.MuserRepository
import com.webauthn4j.WebAuthnManager
import com.webauthn4j.converter.exception.DataConversionException
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.AttestationConveyancePreference
import com.webauthn4j.data.AuthenticationParameters
import com.webauthn4j.data.AuthenticationRequest
import com.webauthn4j.data.AuthenticatorSelectionCriteria
import com.webauthn4j.data.PublicKeyCredentialCreationOptions
import com.webauthn4j.data.PublicKeyCredentialDescriptor
import com.webauthn4j.data.PublicKeyCredentialParameters
import com.webauthn4j.data.PublicKeyCredentialRequestOptions
import com.webauthn4j.data.PublicKeyCredentialRpEntity
import com.webauthn4j.data.PublicKeyCredentialType
import com.webauthn4j.data.PublicKeyCredentialUserEntity
import com.webauthn4j.data.RegistrationParameters
import com.webauthn4j.data.RegistrationRequest
import com.webauthn4j.data.UserVerificationRequirement
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
import com.webauthn4j.data.client.Origin
import com.webauthn4j.data.client.challenge.DefaultChallenge
import com.webauthn4j.server.ServerProperty
import com.webauthn4j.validator.exception.ValidationException
import org.springframework.stereotype.Service
import java.nio.charset.StandardCharsets
import java.util.Base64
import java.util.concurrent.TimeUnit


@Service
class WebAuthn4JServerServiceImpl(
    private val mUserRepository: MuserRepository,
    private val mfidoCredentialRepository: MfidoCredentialRepository
) : WebAuthn4JServerService {

    private val rp = PublicKeyCredentialRpEntity("localhost", "webauthn4j-test")
    private val origin = Origin.create("http://localhost:8080")

    override fun getRegisterOption(userId: String): PublicKeyCredentialCreationOptions {
        val mUser = mUserRepository.findById(userId).orElseThrow { RuntimeException("User not found") }

        val challenge = DefaultChallenge()

        val userInfo = PublicKeyCredentialUserEntity(
            createUserId(mUser.internalId),     // id
            userId,                             // name
            userId,                             // displayName
        )

        val pubKeyCredParams = listOf(
            PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.ES256
            ),
            PublicKeyCredentialParameters(
                PublicKeyCredentialType.PUBLIC_KEY,
                COSEAlgorithmIdentifier.RS256
            )
        )

        val excludeCredentials = mfidoCredentialRepository.findByUserInternalId(mUser.internalId).map { credential ->
            PublicKeyCredentialDescriptor(
                PublicKeyCredentialType.PUBLIC_KEY,
                Base64.getUrlDecoder().decode(credential.credentialId),
                null
            )
        }

        val authenticatorSelectionCriteria = AuthenticatorSelectionCriteria(
            null,
            true,
            UserVerificationRequirement.REQUIRED
        )

        // https://www.w3.org/TR/webauthn/#enumdef-attestationconveyancepreference
        val attestation = AttestationConveyancePreference.NONE

        return PublicKeyCredentialCreationOptions(
            rp,
            userInfo,
            challenge,
            pubKeyCredParams,
            TimeUnit.SECONDS.toMillis(60),
            excludeCredentials,
            authenticatorSelectionCriteria,
            attestation,
            null
        )

    }

    override fun getAuthenticateOption(): PublicKeyCredentialRequestOptions {
        val challenge = DefaultChallenge()

        // TODO allowCredentials
        val allowCredentials = null

        return PublicKeyCredentialRequestOptions(
            challenge,
            TimeUnit.SECONDS.toMillis(60),
            rp.id,
            allowCredentials,
            UserVerificationRequirement.REQUIRED,
            null
        )
    }

    override fun verifyAuthenticateAssertion(
        challengeStr: String,
        assertion: Assertion,
        credentialRecord: CredentialRecord
    ): Boolean {
        // Client properties
        val clientExtensionJSON: String? = null /* set clientExtensionJSON */

        // Server properties
        val challenge = DefaultChallenge(challengeStr)
        val tokenBindingId: ByteArray? = null /* set tokenBindingId */
        val serverProperty = ServerProperty(origin, rp.id!!, challenge, tokenBindingId)

        // expectations
        val allowCredentials: List<ByteArray>? = null
        val userVerificationRequired = true
        val userPresenceRequired = true

        val authenticationRequest = AuthenticationRequest(
            assertion.credentialId,
            assertion.userHandle,
            assertion.authenticatorData,
            assertion.clientDataJSON,
            clientExtensionJSON,
            assertion.signature,
        )

        val authenticationParameters = AuthenticationParameters(
            serverProperty,
            credentialRecord,
            allowCredentials,
            userVerificationRequired,
            userPresenceRequired
        )

        val authenticationData = try {
            WebAuthnManager.createNonStrictWebAuthnManager().parse(authenticationRequest)
        } catch (e: DataConversionException) {
            // If you would like to handle WebAuthn data structure parse error, please catch DataConversionException
            throw e
        }

        try {
            WebAuthnManager.createNonStrictWebAuthnManager().validate(authenticationData, authenticationParameters)
        } catch (e: ValidationException) {
            // If you would like to handle WebAuthn data validation error, please catch ValidationException
            throw e
        }

//        // please update the counter of the authenticator record
//        updateCounter(
//            authenticationData.getCredentialId(),
//            authenticationData.getAuthenticatorData().getSignCount()
//        )

        return true
    }

    private fun createUserId(userId: String): ByteArray {
        return userId.toByteArray(StandardCharsets.UTF_8)
    }

    override fun toUserInternalId(encodedUserHandle: String): String {
        val decoder = Base64.getUrlDecoder()
        val userHandle = decoder.decode(encodedUserHandle)
        return String(userHandle, StandardCharsets.UTF_8)
    }
}
