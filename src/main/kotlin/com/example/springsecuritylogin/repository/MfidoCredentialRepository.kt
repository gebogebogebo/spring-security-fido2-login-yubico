package com.example.springsecuritylogin.repository

import org.springframework.data.jpa.repository.JpaRepository

interface MfidoCredentialRepository : JpaRepository<MfidoCredentialForYubico, Int> {
    fun findByUserInternalId(userInternalId: String): List<MfidoCredentialForYubico>
}
