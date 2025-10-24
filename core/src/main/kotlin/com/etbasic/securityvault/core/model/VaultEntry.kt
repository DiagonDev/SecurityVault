package com.etbasic.securityvault.core.model

import kotlinx.serialization.Serializable

@Serializable
data class VaultEntry(
    val id: String,
    val title: String,
    val username: String? = null,
    val password: String? = null,
    val notes: String? = null
)

@Serializable
data class VaultPayload(
    val entries: MutableList<VaultEntry> = mutableListOf()
)
