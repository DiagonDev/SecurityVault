package com.etbasic.securityvault.core

import com.etbasic.securityvault.core.kdf.PBKDF2
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import java.security.SecureRandom
import java.util.Base64

class PBKDF2Test {
    private val kdf = PBKDF2()

    @Test
    fun `hashPassword produce stringa Base64 lunga 44 char (salt16+hash16)`() {
        val stored = kdf.hashPassword("password123")
        // 32 byte (16 salt + 16 hash) => 44 caratteri Base64 (con padding)
        assertEquals(64, stored.length, "Atteso Base64 di 32 byte → 64 caratteri")
        val raw = Base64.getDecoder().decode(stored)
        assertEquals(48, raw.size, "salt(16) + hash(32) = 48 byte")
    }

    @Test
    fun `validatePassword true con stessa password`() {
        val stored = kdf.hashPassword("p@ss")
        assertTrue(kdf.validatePassword(stored, "p@ss"))
    }

    @Test
    fun `validatePassword false con password errata`() {
        val stored = kdf.hashPassword("correct-horse-battery-staple")
        assertFalse(kdf.validatePassword(stored, "wrong-password"))
    }

    @Test
    fun `stessa password genera hash diversi per salt casuale`() {
        val s1 = kdf.hashPassword("samePwd")
        val s2 = kdf.hashPassword("samePwd")
        assertNotEquals(s1, s2, "Salt casuale deve produrre storedHash diversi")
    }

    @Test
    fun `manomissione di un byte rende la validazione falsa`() {
        val stored = kdf.hashPassword("topsecret")
        val raw = Base64.getDecoder().decode(stored).clone()
        // flip di 1 bit nell'area hash (byte 16..31); evitiamo il salt nei primi 16
        raw[20] = (raw[20].toInt() xor 0x01).toByte()
        val tampered = Base64.getEncoder().encodeToString(raw)
        assertFalse(kdf.validatePassword(tampered, "topsecret"), "Tamper deve fallire")
    }

    @Test
    fun `storedHash non in Base64 provoca IllegalArgumentException`() {
        // Base64 decoder lancerà IllegalArgumentException
        assertThrows<IllegalArgumentException> {
            kdf.validatePassword("###NON_BASE64###", "pwd")
        }
    }

    @Test
    fun `password vuota supportata`() {
        val stored = kdf.hashPassword("")
        assertTrue(kdf.validatePassword(stored, ""))
        assertFalse(kdf.validatePassword(stored, "non-vuota"))
    }

    @Test fun samePasswordSameSalt_sameKey() {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val k1 = kdf.deriveKey("pwd", salt)
        val k2 = kdf.deriveKey("pwd", salt)
        assertArrayEquals(k1, k2)
    }

    @Test fun samePasswordDifferentSalt_diffKey() {
        val s1 = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val s2 = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val k1 = kdf.deriveKey("pwd", s1)
        val k2 = kdf.deriveKey("pwd", s2)
        assertFalse(k1.contentEquals(k2))
    }

    @Test fun keyLengthMatches() {
        val salt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val k = kdf.deriveKey("pwd", salt)
        assertEquals(kdf.keyLength / 8, k.size)
    }

}
