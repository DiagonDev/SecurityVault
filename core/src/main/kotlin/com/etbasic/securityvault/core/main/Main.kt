package com.etbasic.securityvault.core.main

import com.etbasic.securityvault.core.cipher.AesGcmCipher
import com.etbasic.securityvault.core.kdf.PBKDF2
import com.etbasic.securityvault.core.model.VaultHeader
import com.etbasic.securityvault.core.model.VaultHeaderCodec
import com.etbasic.securityvault.core.persistence.FileVaultStore
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.json.Json
import java.io.Console
import java.io.File
import java.security.SecureRandom
import javax.crypto.AEADBadTagException

// Modello semplice per la parte "plaintext" del vault (json)
@Serializable
data class VaultEntry(val id: String, val title: String, val username: String, val password: String, val notes: String? = null)

@Serializable
data class VaultData(val entries: MutableList<VaultEntry> = mutableListOf())

object Main {
    private val json = Json { prettyPrint = true; encodeDefaults = true }

    @JvmStatic
    fun main(args: Array<String>) {
        // directory locale dove salvare i vault (per semplicità)
        val vaultDir = File("vaults")
        val store = FileVaultStore(vaultDir)

        println("Simple SecurityVault — demo CLI")
        loop@ while (true) {
            println()
            println("Scegli: (1) crea  (2) apri  (3) aggiungi  (4) cambia-pw  (5) cancella  (q) esci")
            when (readLineTrim()) {
                "1" -> createVaultFlow(store)
                "2" -> openVaultFlow(store)
                "3" -> addEntryFlow(store)
                "4" -> changePasswordFlow(store)
                "5" -> deleteFlow(store)
                "q", "Q" -> break@loop
                else -> println("scelta non valida")
            }
        }
        println("bye")
    }

    // ---------- utility per input password (Console se disponibile, altrimenti readLine) ----------
    private fun readPassword(prompt: String): CharArray {
        val cons: Console? = System.console()
        return if (cons != null) {
            cons.readPassword(prompt)
        } else {
            // fallback (IDE): legge come stringa (meno sicuro perché visibile)
            print(prompt)
            val line = readLine() ?: ""
            line.toCharArray()
        }
    }

    private fun readLineTrim(): String = readLine()?.trim() ?: ""

    // ---------- Flusso: creare un nuovo vault ----------
    private fun createVaultFlow(store: FileVaultStore) {
        print("Nome file vault (es. myvault.dat): ")
        val filename = readLineTrim().ifEmpty { println("Nome richiesto"); return }

        val pwChars = readPassword("Scegli una master password: ")
        val pw = String(pwChars)
        // zeroizza il char[] originale per buona pratica
        pwChars.fill('\u0000')

        // parametri (didattici) — puoi adattarli alla policy della tua app
        val encIterations = 65536
        val keyLenBytes = 32 // AES-256

        // 1) stored auth hash (usato per verificare la password senza decifrare)
        val authKdf = PBKDF2() // usa default (stesso usato in validatePassword)
        val storedAuthHash = authKdf.hashPassword(pw)

        // 2) enc salt e derivazione chiave
        val encSalt = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val encKdf = PBKDF2(iterationCount = encIterations, keyLength = keyLenBytes * 8)
        val encKey = encKdf.deriveKey(pw, encSalt)

        // 3) crea header
        val header = VaultHeader(
            encSalt = encSalt,
            encIterations = encIterations,
            keyLenBytes = keyLenBytes,
            storedAuthHash = storedAuthHash,
            aadFormat = "sha256(header-json)"
        )

        // 4) plaintext iniziale (vuoto)
        val initialData = VaultData()
        val plaintext = json.encodeToString(initialData).toByteArray(Charsets.UTF_8)

        // 5) AAD = sha256(header-json)
        val aad = VaultHeaderCodec.aadOf(header)

        // 6) cifra e salva (atomicamente)
        val cipher = AesGcmCipher()
        val blob = cipher.encrypt(encKey, plaintext, aad)
        try {
            store.write(filename, header, blob)
            println("Vault creato: ${store.exists(filename)} ($filename)")
        } catch (e: Exception) {
            println("Errore scrittura vault: ${e.message}")
        } finally {
            // azzera key e plaintext in memoria
            encKey.fill(0)
            plaintext.fill(0)
        }
    }

    // ---------- Flusso: aprire/unlock il vault e mostrare entries ----------
    private fun openVaultFlow(store: FileVaultStore) {
        print("Nome file vault da aprire: ")
        val filename = readLineTrim()
        if (!store.exists(filename)) {
            println("File non trovato")
            return
        }

        val pwChars = readPassword("Inserisci la master password: ")
        val pw = String(pwChars)
        pwChars.fill('\u0000')

        try {
            val vf = store.read(filename)
            val header = vf.header

            // verifica password (auth)
            val authKdf = PBKDF2()
            if (!authKdf.validatePassword(header.storedAuthHash, pw)) {
                println("Password errata")
                return
            }

            val encKdf = PBKDF2(iterationCount = header.encIterations, keyLength = header.keyLenBytes * 8)
            val encKey = encKdf.deriveKey(pw, header.encSalt)
            val aad = VaultHeaderCodec.aadOf(header)

            val plain = AesGcmCipher().decrypt(encKey, vf.ciphertext, aad)
            val vaultData = json.decodeFromString<VaultData>(plain.toString(Charsets.UTF_8))

            println("=== Entries (${vaultData.entries.size}) ===")
            vaultData.entries.forEachIndexed { idx, e ->
                println("${idx + 1}) ${e.title}  [${e.username}] -> ${e.password}  notes:${e.notes ?: "-"}")
            }

            // pulizia memoria
            encKey.fill(0)
            plain.fill(0)
        } catch (e: AEADBadTagException) {
            println("Decrittazione fallita (chiave/AAD errata o dati corrotti).")
        } catch (e: Exception) {
            println("Errore aprendo il vault: ${e.message}")
        }
    }

    // ---------- Flusso: aggiungere una entry (legge -> modifica -> riscrive) ----------
    private fun addEntryFlow(store: FileVaultStore) {
        print("Vault filename: ")
        val filename = readLineTrim()
        if (!store.exists(filename)) { println("File non trovato"); return }

        val pwChars = readPassword("Inserisci master password: ")
        val pw = String(pwChars)
        pwChars.fill('\u0000')

        try {
            val vf = store.read(filename)
            val header = vf.header

            // auth
            val authKdf = PBKDF2()
            if (!authKdf.validatePassword(header.storedAuthHash, pw)) {
                println("Password errata"); return
            }

            val encKdf = PBKDF2(iterationCount = header.encIterations, keyLength = header.keyLenBytes * 8)
            val encKey = encKdf.deriveKey(pw, header.encSalt)
            val aad = VaultHeaderCodec.aadOf(header)

            val plain = AesGcmCipher().decrypt(encKey, vf.ciphertext, aad)
            val vaultData = json.decodeFromString<VaultData>(plain.toString(Charsets.UTF_8))

            // input nuova entry
            print("Titolo: "); val title = readLineTrim()
            print("Username: "); val username = readLineTrim()
            val passwordChars = readPassword("Password entry: "); val entryPw = String(passwordChars); passwordChars.fill('\u0000')
            print("Notes (opzionale): "); val notes = readLine()

            val id = System.currentTimeMillis().toString()
            val entry = VaultEntry(id = id, title = title, username = username, password = entryPw, notes = notes)
            vaultData.entries.add(entry)

            // serializza, cifra e riscrivi con stesso header
            val newPlain = json.encodeToString(vaultData).toByteArray(Charsets.UTF_8)
            val newBlob = AesGcmCipher().encrypt(encKey, newPlain, aad)
            store.write(filename, header, newBlob)
            println("Entry aggiunta.")

            // pulizie
            encKey.fill(0)
            plain.fill(0)
            newPlain.fill(0)
        } catch (e: Exception) {
            println("Errore: ${e.message}")
        }
    }

    // ---------- Flusso: cambiare password master ----------
    private fun changePasswordFlow(store: FileVaultStore) {
        print("Vault filename: ")
        val filename = readLineTrim()
        if (!store.exists(filename)) { println("File non trovato"); return }

        val oldPwChars = readPassword("Vecchia master password: ")
        val oldPw = String(oldPwChars); oldPwChars.fill('\u0000')
        val newPwChars = readPassword("Nuova master password: ")
        val newPw = String(newPwChars); newPwChars.fill('\u0000')

        try {
            val vf = store.read(filename)
            val header = vf.header

            // auth vecchia
            val authKdf = PBKDF2()
            if (!authKdf.validatePassword(header.storedAuthHash, oldPw)) {
                println("Vecchia password errata"); return
            }

            // decifra con chiave derivata dalla vecchia pw
            val encKdfOld = PBKDF2(iterationCount = header.encIterations, keyLength = header.keyLenBytes * 8)
            val oldKey = encKdfOld.deriveKey(oldPw, header.encSalt)
            val aadOld = VaultHeaderCodec.aadOf(header)
            val plaintext = AesGcmCipher().decrypt(oldKey, vf.ciphertext, aadOld)
            val vaultData = json.decodeFromString<VaultData>(plaintext.toString(Charsets.UTF_8))

            // ora rigenera header + key con la nuova password
            val newEncSalt = ByteArray(16).also { SecureRandom().nextBytes(it) }
            val newEncIterations = header.encIterations // puoi cambiarlo se vuoi
            val newKeyLen = header.keyLenBytes
            val encKdfNew = PBKDF2(iterationCount = newEncIterations, keyLength = newKeyLen * 8)
            val newKey = encKdfNew.deriveKey(newPw, newEncSalt)
            val newStoredAuth = PBKDF2().hashPassword(newPw)

            val newHeader = header.copy(encSalt = newEncSalt, encIterations = newEncIterations, storedAuthHash = newStoredAuth)

            val newAad = VaultHeaderCodec.aadOf(newHeader)
            val newPlain = json.encodeToString(vaultData).toByteArray(Charsets.UTF_8)
            val newBlob = AesGcmCipher().encrypt(newKey, newPlain, newAad)

            store.write(filename, newHeader, newBlob)
            println("Master password aggiornata.")

            // pulizie
            oldKey.fill(0); newKey.fill(0)
            plaintext.fill(0); newPlain.fill(0)

        } catch (e: Exception) {
            println("Errore cambio password: ${e.message}")
        }
    }

    // ---------- Flusso: cancellare file vault ----------
    private fun deleteFlow(store: FileVaultStore) {
        print("Vault filename da cancellare: ")
        val filename = readLineTrim()
        if (!store.exists(filename)) { println("File non trovato"); return }
        print("Sei sicuro? (y/N): ")
        if (readLineTrim().lowercase() != "y") { println("annullato"); return }
        try {
            val ok = store.delete(filename)
            println("Cancellato: $ok")
        } catch (e: Exception) {
            println("Errore cancellazione: ${e.message}")
        }
    }
}