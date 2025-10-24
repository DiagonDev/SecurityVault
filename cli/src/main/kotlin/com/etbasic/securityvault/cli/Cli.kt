package com.etbasic.securityvault.cli

import com.etbasic.securityvault.core.cipher.AesGcmCipher
import com.etbasic.securityvault.core.kdf.PBKDF2
import com.etbasic.securityvault.core.model.VaultEntry
import com.etbasic.securityvault.core.service.DefaultVaultService
import com.etbasic.securityvault.core.service.VaultService
import com.etbasic.securityvault.core.store.FileVaultStore
import java.util.UUID

object Cli {

    @JvmStatic
    fun main(args: Array<String>) {
        if (args.isEmpty()) return usage()

        val cmd = args[0]
        val path = args.getOrNull(1) ?: "vault.svlt"

        // Wiring
        val kdf = PBKDF2()
        val deriveKey: (String, ByteArray) -> ByteArray = { pwd, salt ->
            // usa qui la TUA implementazione di deriveKey(pwd, salt) (PBKDF2)
            // esempio:
            com.etbasic.securityvault.core.crypto.PasswordAesKeyDeriver()
                .deriveKeyBytes(pwd.toCharArray(), salt, 210_000, 32)
        }
        val store: FileVaultStore = DefaultFileVaultStore() // implementata dal tuo collega
        val cipher = AesGcmCipher()
        val svc: VaultService = DefaultVaultService(kdf, deriveKey, store, cipher)

        when (cmd) {
            "init" -> {
                val master = readPassword("Nuova master password: ")
                svc.create(path, master)
                println("Vault creato: $path")
            }
            "add" -> {
                val master = readPassword("Master password: ")
                svc.open(path, master).use { vh ->
                    val entry = promptEntry()
                    vh.add(entry)
                    vh.save()
                    println("Voce aggiunta: ${entry.title}")
                }
            }
            "list" -> {
                val master = readPassword("Master password: ")
                svc.open(path, master).use { vh ->
                    vh.list().forEachIndexed { i, e ->
                        println("${i + 1}. ${e.title} (id=${e.id})")
                    }
                }
            }
            "get" -> {
                val id = args.getOrNull(2) ?: return println("Uso: get <path> <id>")
                val master = readPassword("Master password: ")
                svc.open(path, master).use { vh ->
                    val e = vh.get(id)
                    println("Title : ${e.title}")
                    println("User  : ${e.username ?: "-"}")
                    println("Pass  : ${e.password ?: "-"}") // ok per MVP
                    println("Notes : ${e.notes ?: "-"}")
                }
            }
            "rm" -> {
                val id = args.getOrNull(2) ?: return println("Uso: rm <path> <id>")
                val master = readPassword("Master password: ")
                svc.open(path, master).use { vh ->
                    if (vh.remove(id)) {
                        vh.save()
                        println("Rimossa $id")
                    } else println("ID non trovato")
                }
            }
            else -> usage()
        }
    }

    private fun usage() {
        println("Uso: vault <init|add|list|get|rm> [path] [args]")
    }

    private fun readPassword(prompt: String): CharArray {
        val console = System.console()
        return (console?.readPassword(prompt) ?: run {
            print(prompt); readln().toCharArray()
        })
    }

    private fun promptEntry(): VaultEntry {
        print("Titolo: "); val title = readln()
        print("Username: "); val user = readln().ifEmpty { null }
        print("Password: "); val pass = readln().ifEmpty { null }
        print("Note: "); val notes = readln().ifEmpty { null }
        return VaultEntry(
            id = UUID.randomUUID().toString(),
            title = title,
            username = user,
            password = pass,
            notes = notes
        )
    }
}
