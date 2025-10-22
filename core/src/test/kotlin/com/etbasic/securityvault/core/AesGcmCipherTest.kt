package com.etbasic.securityvault.core

import org.example.com.etbasic.securityvault.core.cipher.AesGcmCipher
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

class AesGcmCipherTest {

    private val rng = SecureRandom()

    private fun randomKey(len: Int): ByteArray =
        ByteArray(len).also { rng.nextBytes(it) }

    private fun randomBytes(n: Int): ByteArray =
        ByteArray(n).also { rng.nextBytes(it) }

    private fun makeAead() = AesGcmCipher(
        ivSizeBytes = 12,   // default
        tagSizeBytes = 16   // default
    )

    // --- Round-trip senza AAD, per key size 128/192/256 ---
    @Test
    fun roundTrip_noAad_allKeySizes() {
        val plaintext = randomBytes(2048)
        val aead = makeAead()

        listOf(16, 24, 32).forEach { klen ->
            val key = randomKey(klen)
            val ct = aead.encrypt(key, plaintext, aad = null)
            val dec = aead.decrypt(key, ct, aad = null)
            assertArrayEquals(plaintext, dec, "Round-trip fallito per key size $klen")
        }
    }

    // --- Round-trip con AAD ---
    @Test
    fun roundTrip_withAad() {
        val key = randomKey(32)
        val plaintext = randomBytes(4096)
        val aad = """{"version":1,"kdf":"pbkdf2","saltLen":16}""".toByteArray()
        val aead = makeAead()

        val ct = aead.encrypt(key, plaintext, aad)
        val dec = aead.decrypt(key, ct, aad)
        assertArrayEquals(plaintext, dec)
    }

    // --- Plaintext vuoto (lecito in GCM) ---
    @Test
    fun emptyPlaintext_supported() {
        val key = randomKey(16)
        val plaintext = ByteArray(0)
        val aad = "header".toByteArray()
        val aead = makeAead()

        val ct = aead.encrypt(key, plaintext, aad)
        val dec = aead.decrypt(key, ct, aad)
        assertArrayEquals(plaintext, dec)
        // l’output deve almeno contenere IV + TAG
        assertTrue(ct.size >= 12 + 16)
    }

    // --- Tampering: flip di 1 bit nel ciphertext/tag -> AEADBadTagException ---
    @Test
    fun tamperCiphertext_fails() {
        val key = randomKey(32)
        val plaintext = "hello vault".toByteArray()
        val aad = "hdr".toByteArray()
        val aead = makeAead()

        val ct = aead.encrypt(key, plaintext, aad)
        // flip di 1 bit sull’ultimo byte
        ct[ct.lastIndex] = (ct.last().toInt() xor 0x01).toByte()

        assertThrows<AEADBadTagException> {
            aead.decrypt(key, ct, aad)
        }
    }

    // --- AAD diversa in decrypt -> AEADBadTagException ---
    @Test
    fun aadMismatch_fails() {
        val key = randomKey(24)
        val plaintext = "secret".toByteArray()
        val aadEnc = "AAD-v1".toByteArray()
        val aadDec = "AAD-v2".toByteArray()
        val aead = makeAead()

        val ct = aead.encrypt(key, plaintext, aadEnc)
        assertThrows<AEADBadTagException> {
            aead.decrypt(key, ct, aadDec)
        }
    }

    // --- Key size non valida -> IllegalArgumentException ---
    @Test
    fun wrongKeySize_throws() {
        val key = randomKey(15) // non valido
        val aead = makeAead()
        val ex = assertThrows<IllegalArgumentException> {
            aead.encrypt(key, "x".toByteArray(), null)
        }
        assertTrue(ex.message!!.contains("AES key must be"), ex.message)
    }

    // --- Blob troppo corto in decrypt -> IllegalArgumentException ---
    @Test
    fun blobTooShort_throws() {
        val key = randomKey(16)
        val aead = makeAead()
        val tooShort = ByteArray(10) // < IV(12) + TAG(16)
        assertThrows<IllegalArgumentException> {
            aead.decrypt(key, tooShort, null)
        }
    }

    // --- Non-determinismo garantito: IV diverso ad ogni encrypt ---
    @Test
    fun differentIvEachTime() {
        val key = randomKey(32)
        val plaintext = "same message".toByteArray()
        val aead = makeAead()

        val ct1 = aead.encrypt(key, plaintext, null)
        val ct2 = aead.encrypt(key, plaintext, null)

        assertNotEquals(ct1.contentToString(), ct2.contentToString(), "Due cifrature identiche non dovrebbero coincidere")

        // Confronta esplicitamente gli IV (primi 12 byte)
        val iv1 = ct1.copyOfRange(0, 12)
        val iv2 = ct2.copyOfRange(0, 12)
        assertFalse(iv1.contentEquals(iv2), "IV dovrebbe essere diverso ad ogni cifratura")
    }
}
