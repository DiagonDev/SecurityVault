package com.etbasic.securityvault.core.model

import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class VaultHeaderCodecTest {

    private val rng = SecureRandom()

    private fun rand(n: Int) = ByteArray(n).also { rng.nextBytes(it) }

    @Test
    fun `round-trip JSON ok`() {
        val hdr = VaultHeader(
            encSalt = rand(16),
            encIterations = 210_000,
            storedAuthHash = "algo:salt:iter:hash" // quello del tuo KDF
        )

        val bytes = VaultHeaderCodec.toJsonBytes(hdr)
        val back = VaultHeaderCodec.fromJsonBytes(bytes)

        assertEquals(hdr.version, back.version)
        assertArrayEquals(hdr.encSalt, back.encSalt)
        assertEquals(hdr.encIterations, back.encIterations)
        assertEquals(hdr.keyLenBytes, back.keyLenBytes)
        assertEquals(hdr.cipherAlg, back.cipherAlg)
        assertEquals(hdr.ivSizeBytes, back.ivSizeBytes)
        assertEquals(hdr.tagSizeBytes, back.tagSizeBytes)
        assertEquals(hdr.storedAuthHash, back.storedAuthHash)
        assertEquals(hdr.aadFormat, back.aadFormat)
    }

    @Test
    fun `AAD è SHA-256(header-json)`() {
        val hdr = VaultHeader(
            encSalt = rand(16),
            encIterations = 210_000,
            storedAuthHash = "x"
        )
        val aad = VaultHeaderCodec.aadOf(hdr)
        assertEquals(32, aad.size) // SHA-256 → 32 byte
    }
}
