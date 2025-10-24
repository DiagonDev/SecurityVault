package com.etbasic.securityvault.core.model

import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.MessageDigest

/**
 * Questa è una classe helper, i nomi dei metodi sono abbastanza auto esplicativi
 * Serve come punto di riferimento unico per convertire le cose, se lo facessimo in ogni classe
 * potrebbe capitare che ci siano delle divergenze di formato
 */
object VaultHeaderCodec {
    // JSON “stabile”: niente indentazione, niente espliciti null, includi default
    val json = Json {
        prettyPrint = false
        explicitNulls = false
        encodeDefaults = true
    }

    fun toJsonBytes(header: VaultHeader): ByteArray =
        json.encodeToString(header).toByteArray(Charsets.UTF_8)

    fun fromJsonBytes(bytes: ByteArray): VaultHeader =
        json.decodeFromString(bytes.toString(Charsets.UTF_8))

    /** AAD suggerita: SHA-256 dell’header JSON per avere lunghezza fissa */
    fun aadOf(header: VaultHeader): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        return md.digest(toJsonBytes(header))
    }
}
