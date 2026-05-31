package com.arcium.messenger.network

class BluetoothMeshManager {

    fun isSupported(): Boolean = false

    fun startScan() {
        // TODO: BLE GATT server for Arcium mesh service UUID
        // TODO: BLUETOOTH_SCAN + BLUETOOTH_CONNECT permissions required at runtime
    }

    fun stopScan() {
        // TODO: stop BLE scanner
    }

    suspend fun sendToPeer(peerAddress: String, encryptedPacket: ByteArray): Result<Unit> {
        // TODO: connect GATT, write to Arcium mesh characteristic
        return Result.failure(NotImplementedError("TODO: BLE GATT write"))
    }
}
