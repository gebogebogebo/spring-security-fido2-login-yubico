package com.example.springsecuritylogin.service

import com.example.springsecuritylogin.repository.MfidoCredentialForYubico
import com.example.springsecuritylogin.repository.MfidoCredentialRepository
import com.example.springsecuritylogin.repository.MuserRepository
import org.springframework.stereotype.Service
import java.util.Base64


@Service
class FidoCredentialServiceImpl(
    private val mUserRepository: MuserRepository,
    private val mFidoCredentialRepository: MfidoCredentialRepository,
) : FidoCredentialService {
    override fun save(userId: String, attestationVerifyResult: AttestationVerifyResult) {
        val mUser = mUserRepository.findById(userId).orElseThrow { RuntimeException("User not found") }

        val entity = MfidoCredentialForYubico(
            0,
            mUser.internalId,
            attestationVerifyResult.credentialId,
            attestationVerifyResult.signCount,
            attestationVerifyResult.credentialPublicKey
        )
        mFidoCredentialRepository.save(entity)
    }

    /*
    override fun load(userInternalId: String, credentialId: String): Pair<CredentialRecord?,String?> {
        val entityList = mFidoCredentialRepository.findByUserInternalId(userInternalId)
        val mFidoCredential = entityList.find { it.credentialId == credentialId} ?: return null to null

        // deserialize
        val objectConverter = ObjectConverter()
        val attestedCredentialDataConverter = AttestedCredentialDataConverter(objectConverter)
        val deserializedAttestedCredentialData = attestedCredentialDataConverter.convert(mFidoCredential.credentialPublicKey)

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
     */

}
