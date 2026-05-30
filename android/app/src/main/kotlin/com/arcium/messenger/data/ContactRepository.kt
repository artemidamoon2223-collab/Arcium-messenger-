package com.arcium.messenger.data

import com.arcium.messenger.ffi.ArciumCoreWrapper
import javax.inject.Inject
import javax.inject.Singleton

data class Contact(val phone: String, val publicKey: ByteArray, val name: String)

@Singleton
class ContactRepository @Inject constructor(
    private val core: ArciumCoreWrapper,
) {
    /** Run PSI to discover which of the supplied phone numbers are Arcium users. */
    suspend fun discoverContacts(phoneNumbers: List<String>): List<Contact> {
        // TODO: hash phone numbers with SHA256[0..8] LE (canonical contact hash)
        // TODO: call core.submitPsiQuery(hashes) → BooleanArray
        // TODO: fetch public keys for matched contacts from Solana
        return emptyList()
    }

    /** List all locally stored contacts. */
    fun getAllContacts(): List<Contact> {
        // TODO: read from encrypted SQLite via core-storage
        return emptyList()
    }
}
