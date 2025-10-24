package com.etbasic.securityvault.core.kdf

interface KDF {
    /**
     * Calcola e ritorna una stringa pronta per la memorizzazione che rappresenta
     * il risultato dell'hashing della password
     * @param password la password in chiaro da derivare
     *
     * @return una stringa contenente il salt e l'hash, per la memorizzazione nel DB
     *
     */
    fun hashPassword(password: String): String
    /**
     * Verifica se la password fornita corrisponde all'hash memorizzato
     *
     * @param storedHash la stringa salvata nel DB
     * @param inputPassword la password fornita dall'utente per il login
     *
     * @return true se la password è corretta
     *
     */
    fun validatePassword(storedHash: String, inputPassword: String): Boolean
    /*
    * Crea la chiave derivata da utilizzare per cifrare i dati con AES
    *
    * @param password la password inserita dall'utente
    * @param salt il salt utilizzato per quella password
    *
    * @return la chiave derivata
    *
    * */
    fun deriveKey(password: String, salt: ByteArray): ByteArray
}