package org.example.kdf
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec
import java.security.SecureRandom
import java.util.Base64

class PBKDF2(
    val iterationCount: Int = 65536,
    val keyLength: Int = 256
) : KDF {

    override fun hashPassword(password: String): String {
        // È la lunghezza del salt in byte, più è lungo => meno rischio di collisioni ( serve anche per evitare attacchi con le rainbow table)
        val salt = ByteArray(16)
        // Genera i numeri casuali del salt in base alla sua lunghezza
        SecureRandom().nextBytes(salt)
        /*
        * @param iterationCount => PBKDF2 applica ripetutamente HMAC-SHA256 65536 volte.
        * Più alto = più lento da calcolare = più difficile da attaccare con brute-force.
        * Va adeguato in base all’hardware e alla politica di sicurezza
        * @param keyLength è la lunghezza in BIT della key generata
        * */
        //Costruisce la specifica per PBKDF2
        val spec = PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
        // viene scelto il tipo di algoritmo per cifrare la master password
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        // viene effettivamente fatto l´hash della password
        // encoded restituisce l’array di byte della chiave derivata
        val hash = factory.generateSecret(spec).encoded
        // Concatena salt + hash e li codifica in Base64(cosi che possano essere salvati) come una singola stringa da memorizzare
        // Memorizzando salt+hash insieme si mantiene assieme il salt necessario per la verifica
        return Base64.getEncoder().encodeToString(salt + hash)
    }

    /*
    * @param sotredHash è il salt + hash salvato nel database
    * @param inputPassword è la password inserita dall'utente per "accedere" all'applicazione
    * */
    override fun validatePassword(storedHash: String, inputPassword: String): Boolean {
        // decodifica l'hash per farlo tornare in forma di byte
        val decodedHash = Base64.getDecoder().decode(storedHash)
        // copia i primi 16 byte e li associa al salt
        val salt = decodedHash.copyOfRange(0, 16)
        // copia i byte successivi al salt che sono l'hash effettivo della password
        val originalHash = decodedHash.copyOfRange(16, decodedHash.size)
        val spec = PBEKeySpec(inputPassword.toCharArray(), salt, iterationCount, keyLength)
        val factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        val newHash = factory.generateSecret(spec).encoded
        // compara l´hash generato per la password fornita in input dall'utente con l'hash estratto dal database
        return originalHash.contentEquals(newHash)
    }

    // Serve per creare la chiave da fornire ad AES
    override fun deriveKey(password: String, salt: ByteArray): ByteArray {
        val spec = javax.crypto.spec.PBEKeySpec(password.toCharArray(), salt, iterationCount, keyLength)
        val factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")
        return factory.generateSecret(spec).encoded
    }

}