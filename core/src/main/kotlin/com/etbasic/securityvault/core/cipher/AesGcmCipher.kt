package com.etbasic.securityvault.core.cipher

import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.spec.SecretKeySpec

class AesGcmCipher(
    private val ivSizeBytes: Int = 12,   // 96 bit, raccomandato per GCM
    private val tagSizeBytes: Int = 16,  // 128 bit
    private val rng: SecureRandom = SecureRandom()
) : AeadCipher {

    private val transformation = "AES/GCM/NoPadding"
    private val algorithm = "AES"

    override fun encrypt(
        key: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray?
    ): ByteArray {
        // plaintext può essere anche vuoto (GCM supporta lunghezza 0).
        // aad può essere null (nessuna AAD).
        // require è ovvio, key deve essere di grandezza precisa
        require(key.size == 16 || key.size == 24 || key.size == 32) {
            "AES key must be 16, 24, or 32 bytes"
        }

        // Genera IV/nonce casuale (12 byte raccomandati per GCM)
        val iv = ByteArray(ivSizeBytes).also { rng.nextBytes(it) }

        // Prepara chiave e parametri GCM (tag a 128 bit = 16 byte)
        val sk = SecretKeySpec(key, algorithm) // "AES"
        val gcmSpec = GCMParameterSpec(tagSizeBytes * 8, iv)

        // Inizializza il Cipher in ENCRYPT_MODE con AES/GCM/NoPadding
        val cipher = Cipher.getInstance(transformation) // "AES/GCM/NoPadding"
        cipher.init(Cipher.ENCRYPT_MODE, sk, gcmSpec)

        // (Opzionale) Collega AAD prima dei dati: autenticata ma non cifrata
        if (aad != null) cipher.updateAAD(aad)

        //  Cifra e calcola il TAG in un colpo solo
        //    doFinal() ritorna: ciphertext || tag (tag in coda)
        val ctPlusTag = cipher.doFinal(plaintext)

        // Componi l’output nel layout scelto: IV || (ciphertext || tag)
        // Questa scelta è arbitraria, in questo caso ci uniformiamo al formato standard
        val out = ByteArray(iv.size + ctPlusTag.size)
        System.arraycopy(iv,        0, out, 0,          iv.size)
        System.arraycopy(ctPlusTag, 0, out, iv.size,    ctPlusTag.size)

        // azzera IV temporaneo (non strettamente necessario, ma buona pratica)
        zeroize(iv)

        // Ritorna il blob completo pronto da salvare nel file vault
        return out
    }

    @Throws(AEADBadTagException::class)
    override fun decrypt(
        key: ByteArray,
        ciphertextWithIv: ByteArray,
        aad: ByteArray?
    ): ByteArray {

        require(key.size == 16 || key.size == 24 || key.size == 32) {
            "AES key must be 16, 24, or 32 bytes"
        }
        require(ciphertextWithIv.size >= ivSizeBytes + tagSizeBytes) {
            "Ciphertext too short"
        }

        // Parsing del blob: estrai IV e il blocco 'ciphertext||tag'
        val iv = ciphertextWithIv.copyOfRange(0, ivSizeBytes)
        val ctPlusTag = ciphertextWithIv.copyOfRange(ivSizeBytes, ciphertextWithIv.size)

        // Prepara chiave e parametri GCM con lo stesso IV
        val sk = SecretKeySpec(key, algorithm)                    // "AES"
        val gcm = GCMParameterSpec(tagSizeBytes * 8, iv)          // tag 128 bit

        // Inizializza cipher in DECRYPT_MODE e ri-applica l'AAD identica alla cifratura
        val cipher = Cipher.getInstance(transformation)           // "AES/GCM/NoPadding"
        cipher.init(Cipher.DECRYPT_MODE, sk, gcm)
        if (aad != null) cipher.updateAAD(aad)

        // Verifica il TAG e, se valido, restituisce il plaintext
        //    Se key/IV/AAD o i dati sono errati/manomessi → AEADBadTagException
        return try {
            cipher.doFinal(ctPlusTag)
        } finally {
            // azzera temporanei
            iv.fill(0); ctPlusTag.fill(0)
        }
    }


    private fun zeroize(arr: ByteArray?) {
        if (arr == null) return
        for (i in arr.indices) arr[i] = 0
    }
}