package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MfidoCredential
import com.example.springsecuritylogin.repository.MfidoCredentialRepository
import com.example.springsecuritylogin.repository.MuserRepository
import com.webauthn4j.converter.AttestedCredentialDataConverter
import com.webauthn4j.converter.util.ObjectConverter
import com.webauthn4j.credential.CredentialRecord
import com.webauthn4j.credential.CredentialRecordImpl
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput
import com.webauthn4j.util.Base64UrlUtil
import org.springframework.stereotype.Service


@Service
class FidoCredentialServiceImpl(
    private val mUserRepository: MuserRepository,
    private val mFidoCredentialRepository: MfidoCredentialRepository,
) : FidoCredentialService {
    override fun save(userId: String, credentialId: ByteArray, credentialRecord: CredentialRecord) {
        val mUser = mUserRepository.findById(userId).orElseThrow { RuntimeException("User not found") }

        // encode
        val encodedCredentialId = Base64UrlUtil.encodeToString(credentialId)

        // serialize
        val objectConverter = ObjectConverter()
        val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)
        val serializedAttestedCredentialData =
            attestedCredentialDataConverter.convert(credentialRecord.attestedCredentialData)

//        val attestationStatementEnvelope = AttestationStatementEnvelope(credentialRecord.attestationStatement)
        var attestationStatementEnvelope = AttestationStatementEnvelope()
        // TODO attestationStatement は NoneAttestationStatement
        attestationStatementEnvelope.AttestationStatementEnvelope(credentialRecord.attestationStatement)

//
        val serializedEnvelope = objectConverter.cborConverter.writeValueAsBytes(attestationStatementEnvelope)

//        val serializedTransports = objectConverter.jsonConverter.writeValueAsString(authenticator.transports)
//        val serializedAuthenticatorExtensions =
//            objectConverter.cborConverter.writeValueAsBytes(authenticator.authenticatorExtensions)
//        val serializedClientExtensions =
//            objectConverter.jsonConverter.writeValueAsString(authenticator.clientExtensions)

        // save
//        entityManager.persist(
//            Credentials(
//                Base64UrlUtil.encodeToString(credentialId),
//                serializedAttestedCredentialData,
//                serializedEnvelope,
//                serializedTransports,
//                serializedAuthenticatorExtensions,
//                serializedClientExtensions,
//                authenticator.counter
//            )
//        )

        val entity = MfidoCredential(0, encodedCredentialId, mUser.internalId, serializedAttestedCredentialData)
        mFidoCredentialRepository.save(entity)
    }

    override fun load(userInternalId: String, credentialId: String): Pair<CredentialRecord?,String?> {
        val entityList = mFidoCredentialRepository.findByUserInternalId(userInternalId)
        val mFidoCredential = entityList.find { it.credentialId == credentialId} ?: return null to null

        // deserialize
        val objectConverter = ObjectConverter()
        val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)
        val deserializedAttestedCredentialData = attestedCredentialDataConverter.convert(mFidoCredential.ateestedCredentialData)

        // TODO ???
        val attestationStatement = NoneAttestationStatement()
        val authenticatorExtensions =
            AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput>()

        val credentialRecord = CredentialRecordImpl(
            attestationStatement,
            null,
            null,
            null,
            0,      // counter
            deserializedAttestedCredentialData,
            authenticatorExtensions,
            null,
            null,
            null
        )

        val mUser = mUserRepository.findByInternalId(mFidoCredential.userInternalId) ?: return null to null

        return credentialRecord to mUser.id
    }

}
