package org.example.com.etbasic.securityvault.core.cipher

import javax.crypto.AEADBadTagException


interface AeadCipher {
    /**
     * @param key chiave derivata fornita da kdf
     * @param plaintext byte in chiaro che vogliamo mettere nel vault (es. file con passwords)
     * @param aad sono dati non cifrati, servono per impedire manomissioni (entra nel calcolo del TAG)
     * @return bytearray: IV (nonce) || CIPHERTEXT (testo cifrato) || TAG (codice di autenticazione)
     * IV serve per rendere la cifratura non deterministica cambiando sempre, altrimenti un attaccante capirebbe
     * che il testo cifrato non è cambiato anche senza password. Non deve essere segreto
     * */
    fun encrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray

    /**
     * @param key la stessa chiave derivata usata in cifratura
     * @param ciphertextWithIv blob completo nel formato: IV || CIPHERTEXT || TAG
     * @param aad gli stessi dati AAD usati in cifratura; se differiscono la verifica fallisce
     * @return il plaintext originale in chiaro
     * @throws javax.crypto.AEADBadTagException se il TAG non è valido (chiave/IV/AAD errati o dati manomessi)
     * @throws IllegalArgumentException se gli input non sono nel formato atteso (es. blob troppo corto)
     */
    @Throws(AEADBadTagException::class)
    fun decrypt(key: ByteArray, ciphertextWithIv: ByteArray, aad: ByteArray? = null): ByteArray
}
