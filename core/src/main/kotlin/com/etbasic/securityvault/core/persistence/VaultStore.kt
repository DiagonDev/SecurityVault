package com.etbasic.securityvault.core.persistence

import com.etbasic.securityvault.core.model.VaultHeader
import com.etbasic.securityvault.core.persistence.FileVaultStore.VaultFile

interface VaultStore {
    /**
     * blob := blocco di dati binari
     * Salva il blob del vault (nonce + ciphertext + tag) in modo atomico.
     * Ritorna il Path del file salvato.
     */
    fun write(filename: String, header: VaultHeader, ciphertext: ByteArray)

    /** Carica e ritorna il blob completo; lancia VaultNotFoundException se non esiste */
    fun read(filename: String): VaultFile

    /** Rimuove il file del vault (opzionale: con backup) */
    fun exists(filename: String): Boolean

    /** Controlla se il vault esiste */
    fun delete(filename: String): Boolean
}