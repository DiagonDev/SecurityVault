package com.etbasic.securityvault.core.persistence

import com.etbasic.securityvault.core.model.VaultHeader
import com.etbasic.securityvault.core.model.VaultHeaderCodec
import java.io.File
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.StandardCopyOption

/**
 * Semplice FileVaultStore didattico.
 * Formato del file sul disco: [4 byte BE headerLen] [headerJsonBytes] [ciphertext||tag (blob)]
 *
 * Questa classe espone funzioni minimali: write, read, delete, exists.
 * È pensata per essere semplice e leggibile, non per produzione.
 */
class FileVaultStore(private val dir: File) : VaultStore {

    init {
        if (!dir.exists()) dir.mkdirs()
        require(dir.isDirectory) { "Provided path is not a directory: ${dir.path}" }
    }

    data class VaultFile(val header: VaultHeader, val ciphertext: ByteArray)

    /**
     * Scrive atomically il file vault. Se il file già esiste viene sovrascritto.
     */
    @Throws(IOException::class)
    override fun write(filename: String, header: VaultHeader, ciphertext: ByteArray) {
        val headerBytes = VaultHeaderCodec.toJsonBytes(header)
        val headerLen = headerBytes.size

        val out = ByteBuffer.allocate(4 + headerLen + ciphertext.size).order(ByteOrder.BIG_ENDIAN)
        out.putInt(headerLen)
        out.put(headerBytes)
        out.put(ciphertext)
        val bytes = out.array()

        val target = dir.toPath().resolve(filename)

        // Write to temp file then atomically move
        val tmp = Files.createTempFile(dir.toPath(), "vault", ".tmp")
        try {
            Files.write(tmp, bytes)
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } catch (e: Exception) {
                // Se ATOMIC_MOVE non è supportato, esegui rename non-atomico come fallback
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING)
            }
        } finally {
            // cerca di eliminare il tmp se esiste ancora
            try { Files.deleteIfExists(tmp) } catch (_: Exception) {}
            // azzera l'array temporaneo per buona pratica (potrebbe rimanere in memoria)
            bytes.fill(0)
            headerBytes.fill(0)
        }
    }

    /**
     * Legge il file e restituisce header + ciphertext. Lancia IOException se il file non esiste
     * o IllegalArgumentException se il file è malformato.
     */
    @Throws(IOException::class, IllegalArgumentException::class)
    override fun read(filename: String): VaultFile {
        val target = dir.toPath().resolve(filename)
        val all = Files.readAllBytes(target)
        try {
            if (all.size < 4) throw IllegalArgumentException("File troppo corto per contenere la lunghezza dell'header")
            val bb = ByteBuffer.wrap(all).order(ByteOrder.BIG_ENDIAN)
            val headerLen = bb.int
            if (headerLen <= 0 || headerLen > all.size - 4) throw IllegalArgumentException("Header length non valida: $headerLen")
            val headerBytes = ByteArray(headerLen)
            bb.get(headerBytes)
            val cipherBytes = ByteArray(bb.remaining())
            bb.get(cipherBytes)

            val header = VaultHeaderCodec.fromJsonBytes(headerBytes)

            // azzera i buffer temporanei non necessari
            headerBytes.fill(0)

            return VaultFile(header, cipherBytes)
        } finally {
            // non azzeriamo `all` perché non accessibile qui dopo il ritorno in modo semplice;
            // in un progetto più avanzato considerare l'uso di direct buffers o secure containers
        }
    }

    override fun exists(filename: String): Boolean = Files.exists(dir.toPath().resolve(filename))

    @Throws(IOException::class)
    override fun delete(filename: String): Boolean = Files.deleteIfExists(dir.toPath().resolve(filename))
}
