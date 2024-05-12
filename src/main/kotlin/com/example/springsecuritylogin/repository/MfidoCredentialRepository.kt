package com.example.springsecuritylogin.repository

import org.springframework.data.jpa.repository.JpaRepository

interface MfidoCredentialRepository : JpaRepository<MfidoCredential, Int> {
    fun findByUserInternalId(userInternalId: String): List<MfidoCredential>
}
