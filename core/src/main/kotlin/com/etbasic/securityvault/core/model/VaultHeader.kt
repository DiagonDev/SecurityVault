package com.etbasic.securityvault.core.model

import com.etbasic.securityvault.core.json.Base64ByteArraySerializer
import kotlinx.serialization.Serializable

/**
 * Serve a:
 *  1- Verificare password
 *  2- Derivare la chiave di cifratura
 *  3- Capire com'è stata fatta la cifratura
 *  4- Mostrare come ho costruito l'AAD
 */
@Serializable
data class VaultHeader(
    // Versioning per evolvere il formato
    val version: Int = 1,

    // 1-Parametri KDF della chiave di cifratura (separati dal KDF "auth")
    val kdfAlg: String = "PBKDF2WithHmacSHA256",
    @Serializable(with = Base64ByteArraySerializer::class)
    val encSalt: ByteArray,
    val encIterations: Int,
    val keyLenBytes: Int = 32, // 32 → AES-256

    // 2-Parametri del cipher (così il reader sa come decifrare)
    val cipherAlg: String = "AES/GCM/NoPadding",
    val ivSizeBytes: Int = 12,
    val tagSizeBytes: Int = 16,

    // 3-Autenticazione password (prodotto dal KDF del collega)
    val storedAuthHash: String,

    // 4-AAD info (facoltativo, ma utile per auto-documentare)
    val aadFormat: String = "header-json" // o "sha256(header-json)"
)
