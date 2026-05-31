package com.arcium.messenger.data

import com.arcium.messenger.ffi.ArciumCoreWrapper

data class Contact(val phone: String, val publicKey: ByteArray, val name: String)

class ContactRepository(private val core: ArciumCoreWrapper = ArciumCoreWrapper()) {

    suspend fun discoverContacts(phoneNumbers: List<String>): List<Contact> {
        // TODO: hash phones with SHA256[0..8] LE, call core.submitPsiQuery()
        // TODO: fetch public keys for matched contacts from Solana
        return emptyList()
    }

    fun getAllContacts(): List<Contact> {
        // TODO: read from encrypted SQLite via core-storage
        return emptyList()
    }
}
