package org.example.cipher


interface AeadCipher {
    /**
     * @param key chiave derivata fornita da kdf
     * @param plaintext byte in chiaro che vogliamo mettere nel vault (es. file con passwords)
     * @param aad sono dati non cifrati, servono per impedire manomissioni (entra nel calcolo del TAG)
     * @return bytearray: IV (nonce) || CIPHERTEXT (testo cifrato) || TAG (codice di autenticazione)
     * */
    fun encrypt(key: ByteArray, plaintext: ByteArray, aad: ByteArray? = null): ByteArray

    /**
     * Decritta un blob prodotto da [encrypt] verificando l'integrità/autenticità.
     *
     * @param key la stessa chiave derivata usata in cifratura (16/24/32 byte)
     * @param ciphertextWithIv blob completo nel formato: IV || CIPHERTEXT || TAG
     * @param aad gli stessi dati AAD usati in cifratura; se differiscono la verifica fallisce
     * @return il plaintext originale in chiaro
     * @throws javax.crypto.AEADBadTagException se il TAG non è valido (chiave/IV/AAD errati o dati manomessi)
     * @throws IllegalArgumentException se gli input non sono nel formato atteso (es. blob troppo corto)
     */
    @Throws(javax.crypto.AEADBadTagException::class)
    fun decrypt(key: ByteArray, ciphertextWithIv: ByteArray, aad: ByteArray? = null): ByteArray
}
