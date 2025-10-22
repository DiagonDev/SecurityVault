# SecurityVault

This project uses [Gradle](https://gradle.org/).
To build and run the application, use the *Gradle* tool window by clicking the Gradle icon in the right-hand toolbar,
or run it directly from the terminal:

* Run `./gradlew run` to build and run the application.
* Run `./gradlew build` to only build the application.
* Run `./gradlew check` to run all checks, including tests.
* Run `./gradlew clean` to clean all build outputs.

Note the usage of the Gradle Wrapper (`./gradlew`).
This is the suggested way to use Gradle in production projects.

[Learn more about the Gradle Wrapper](https://docs.gradle.org/current/userguide/gradle_wrapper.html).

[Learn more about Gradle tasks](https://docs.gradle.org/current/userguide/command_line_interface.html#common_tasks).

This project follows the suggested multi-module setup and consists of the `app` and `utils` subprojects.
The shared build logic was extracted to a convention plugin located in `buildSrc`.

This project uses a version catalog (see `gradle/libs.versions.toml`) to declare and version dependencies
and both a build cache and a configuration cache (see `gradle.properties`).

# 🛡️ SecureVault – MVP

## Descrizione
**SecureVault** è un password manager **locale e sicuro**, scritto in **Kotlin (JVM)**.  
Il progetto ha lo scopo di fornire un prototipo (*MVP*) che implementa un **vault cifrato** accessibile tramite **master password**, senza connessione di rete.

Tutti i dati vengono salvati in un unico file `.vault`, cifrato e autenticato con algoritmi moderni (PBKDF2 + AES-GCM).

---

## 🎯 Obiettivi
- Conservare credenziali sensibili in modo **sicuro e completamente offline**.  
- Permettere all’utente di **creare, aprire e gestire** il proprio vault cifrato.  
- Fornire una **CLI minimale** per le operazioni di base.  
- Garantire **integrità e confidenzialità** del contenuto con derivazione di chiave sicura (KDF).

---

## ⚙️ Requisiti funzionali

### 1. Creazione Vault
- L’utente inserisce una master password.
- Viene generato un nuovo file `.vault` contenente una struttura vuota e i parametri crittografici (salt, KDF, ecc).

### 2. Apertura Vault
- Dato un file `.vault` e una master password corretta, il contenuto viene decifrato e mostrato.
- Password errata → apertura fallisce senza rivelare informazioni.

### 3. Gestione voci (CRUD)
- **Aggiungi** voce: `name`, `username`, `password`, `url?`, `note?`, `createdAt`, `updatedAt`.
- **Modifica** voce esistente.
- **Elimina** voce.
- **Lista** voci salvate (almeno `name` + `username` visibili).

### 4. Salvataggio
- Il contenuto del vault viene **serializzato in JSON**, cifrato e autenticato con AEAD (AES-GCM), poi scritto su file.

### 5. CLI minimale
- Menu testuale con le seguenti opzioni:
  1. Crea / Apri vault  
  2. Aggiungi voce  
  3. Mostra elenco voci  
  4. Salva  
  5. Esci

---

## 🔐 Requisiti di sicurezza

### 1. Derivazione chiave (KDF)
- MVP: `PBKDF2-HMAC-SHA256`
- Iterazioni: sufficienti per un tempo di derivazione di ~250–500 ms su macchina locale.
- Salt casuale: 16–32 byte.
- Futuro upgrade: `Argon2id`.

### 2. Cifratura
- Algoritmo: `AES-256-GCM` (AEAD → autenticazione + confidenzialità).
- Nonce (IV): 12 byte generati casualmente a ogni salvataggio.
- AAD: contiene intestazione `MAGIC + versione` per legare header e payload.

### 3. Integrità
- Qualsiasi alterazione del file `.vault` causa fallimento della decifratura (tag AEAD non valido).

### 4. Sicurezza generale
- Nessuna comunicazione di rete.
- Nessun log contenente segreti o errori dettagliati.
- Tentativi di accesso errati non rivelano la validità della password.

### 5. Gestione memoria
- Dopo l’uso, la master password e le chiavi derivate vengono **azzerate in RAM** (*best-effort* su JVM).

---

### 🧩 Task CORE

- [ ] Definire `Kdf`, `AeadCipher`, implementare `Pbkdf2Kdf` e `AesGcmCipher`.
- [ ] Definire `VaultHeader`, serializzazione JSON (Kotlinx Serialization o Jackson).
- [ ] Implementare `FileVaultStore` con layout file e AAD.
- [ ] Implementare `DefaultVaultService` e `DefaultVaultHandle`.
- [ ] Utility di zeroizzazione e gestione errori dedicati.
- [ ] Test unitari su KDF / AES / Store.

---

### ✅ Definition of Done

- `VaultService` passa test: **crea / apre / salva / CRUD**.  
- Tentativi con password errata o file manomesso → **falliscono in modo sicuro**.  
- Nessuna fuga di informazioni sensibili o log di debug contenenti segreti.

---
### 🧩 Task CLI

- [ ] Schermata iniziale: “Crea / Apri”.
- [ ] Lettura sicura della master password.
- [ ] Menu CRUD + salvataggio.
- [ ] Form di input voci (campi obbligatori / opzionali).
- [ ] Stampa elenco (senza password in chiaro).
- [ ] Integrazione con `VaultService` (nessuna dipendenza interna al core).
- [ ] Test manuali end-to-end.

---

### ✅ Definition of Done

- Flusso completo **usabile da terminale**, senza stacktrace o crash.  
- Messaggi chiari e coerenti per l’utente.  
- Tutte le funzioni principali (`Crea`, `Apri`, `Aggiungi`, `Mostra`, `Salva`, `Esci`) funzionano end-to-end.

---

## 🧩 Coordinamento

- **Core → App:** API pubbliche di `VaultService` + modello dati.
- **App → Core:** nessuna conoscenza dei dettagli crittografici.
- **Condivisione:** documentazione minima (`core/README.md` con API esposte).

