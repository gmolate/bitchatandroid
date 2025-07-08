# BitChat - Android Port (In Progress)

This project is an Android port of the BitChat application, originally an iOS secure, decentralized, peer-to-peer messaging app using Bluetooth mesh networking.

## Current Status

This port is currently under development. Core functionalities and services have been scaffolded, and initial UI components are in place. Key areas include:

*   **Bluetooth LE:** `BluetoothMeshService.kt` provides the foundation for scanning, advertising, and GATT server/client operations. It's designed to run as a Foreground Service. **Actual UUIDs need to be updated from the iOS version.**
*   **Encryption:** `EncryptionService.kt` outlines methods for end-to-end encryption (X25519 key exchange, AES-GCM for messages, Ed25519 signatures, HKDF, PBKDF2). **Full BouncyCastle integration for reliable X25519/Ed25519 is a critical pending task.**
*   **Protocol Handling:** `BitchatProtocol.kt` (with `BinaryProtocol` object) defines data structures (`BitchatPacket`, `BitchatMessage`) and outlines serialization/deserialization logic. **Placeholders for LZ4 compression and PKCS#7 padding need to be replaced with actual implementations.**
*   **UI (Jetpack Compose):** `ChatScreen.kt` provides a basic chat interface with message display, input field, and runtime permission handling (Bluetooth, Location, Notifications).
*   **ViewModel:** `ChatViewModel.kt` manages UI state using StateFlows and handles basic user interactions and command parsing.
*   **Data Storage:** `DataStorageService.kt` uses Jetpack DataStore for user preferences and Android Keystore for secure storage of identity keys and wrapped channel keys.
*   **Utilities:** `CompressionUtil.kt` (using lz4-java), `BloomFilterUtil.kt` (using Guava), `NotificationService.kt`, and `MessageMetadataService.kt` (for message tracking) have been created.

## Architecture Overview (Android)

The Android version aims to mirror the iOS architecture where sensible, adapting to Android best practices:

*   **UI Layer:** Jetpack Compose (`ChatScreen.kt`, `MessageItem.kt`).
*   **ViewModel Layer:** `ChatViewModel.kt` using Android Architecture Components (`AndroidViewModel`).
*   **Service Layer:**
    *   `BluetoothMeshService.kt`: Manages all BLE operations. Runs as a Foreground Service.
    *   `EncryptionService.kt`: Handles cryptographic tasks.
    *   `BitchatProtocol.kt` (with internal `BinaryProtocol` object): Defines message structures and handles serialization/deserialization.
    *   `MessageMetadataService.kt`: Tracks message delivery status, ACKs, and basic retry logic.
*   **Data Layer:**
    *   `DataStorageService.kt`: Manages persistent data using Jetpack DataStore (for preferences, encrypted keys) and Android Keystore (for identity and wrapping keys).
*   **Utilities (`utils` package & services):**
    *   `CompressionUtil.kt` (for LZ4).
    *   `BloomFilterUtil.kt` (for Guava BloomFilter).
    *   `NotificationService.kt`.

## Key Android-Specific Considerations Addressed

*   **Permissions:** Runtime handling for Bluetooth (SCAN, CONNECT, ADVERTISE), Fine Location, and Post Notifications (API 33+) is implemented in `ChatScreen.kt` using Accompanist Permissions. Manifest entries are in place.
*   **Background Execution:** `BluetoothMeshService` is configured as a Foreground Service with a persistent notification.
*   **Secure Storage:** Android Keystore is utilized by `DataStorageService` for cryptographic keys.
*   **Modern Android Development Stack:** Kotlin, Jetpack Compose, Coroutines, Flow, AndroidX libraries, Jetpack DataStore.
*   **SDK Versioning:** Targets API 34, minSdk 29. Version-specific checks are noted where necessary.

## TODOs / Next Steps (High-Level from current development phase)

1.  **Critical: Replace Placeholder UUIDs:** Update `BITCHAT_SERVICE_UUID` and `BITCHAT_CHARACTERISTIC_UUID` in `BluetoothMeshService.kt` with the actual UUIDs used by the iOS application to ensure interoperability.
2.  **Finalize Cryptography Implementation (`EncryptionService.kt`):**
    *   Fully integrate BouncyCastle for reliable X25519 key generation/agreement and Ed25519 signing/verification. Ensure the BouncyCastle provider is correctly initialized.
    *   Implement secure shared secret management post-key-exchange (e.g., map peer IDs to derived shared secrets).
    *   Ensure PBKDF2 for channel passwords is robust and salts are handled correctly.
3.  **Complete Protocol Implementation (`BinaryProtocol` in `BitchatProtocol.kt`):**
    *   Replace placeholder calls to `LZ4Util` and `PKCS7Util` with actual calls to `CompressionUtil.kt` and a proper PKCS#7 implementation (either custom or from a library if BouncyCastle provides a suitable one).
    *   Ensure correct order of operations: (for sending private UserMessage) -> compress -> pad -> encrypt. (for receiving) -> decrypt -> unpad -> decompress.
    *   Implement robust handling of `originalLength` for LZ4 decompression, or adapt to a streaming LZ4 format if the iOS app uses one.
    *   Implement message fragmentation and reassembly within `BluetoothMeshService` if messages (after encryption/compression) exceed BLE MTU.
4.  **Full Service Integration & Data Flow:**
    *   Implement proper service binding in `MainActivity.kt` to connect to `BluetoothMeshService` and provide the instance to `ChatViewModel`.
    *   Connect `ChatViewModel` to `BluetoothMeshService` to send/receive actual BLE data (serialized `BitchatMessage` payloads).
    *   Integrate `MessageMetadataService` fully with `ChatViewModel` and `BluetoothMeshService` for reliable message status tracking and UI updates (e.g., delivery ticks).
    *   Ensure `EncryptionService` is correctly used by `BinaryProtocol` and `ChatViewModel` (for channel password hashing).
5.  **Refine UI and UX (`ChatScreen.kt` and new screens):**
    *   Display message delivery/read statuses in `MessageItem`.
    *   Implement UI for channel management: creating new channels (with optional password), joining existing channels (prompting for password if needed), listing available/joined channels.
    *   (Optional for initial functional branch) Implement UI to display discovered/connected peers and their status.
    *   (Optional) Add an application settings screen (e.g., for changing display name, managing identity key - though key management should be mostly automatic).
6.  **Error Handling and Stability:**
    *   Implement comprehensive error handling throughout all layers (BLE operations, crypto, serialization, UI).
    *   Propagate errors gracefully to the UI via `ChatViewModel`.
7.  **Thorough Testing:**
    *   Expand unit tests for `EncryptionService` (with BouncyCastle), `BinaryProtocol` (with actual compression/padding), `DataStorageService` (with Robolectric/instrumented tests for Keystore/DataStore), and `MessageMetadataService`.
    *   Develop integration tests for interactions between services (e.g., ViewModel sending a message through the stack).
    *   Create UI tests using Jetpack Compose testing framework.
    *   Test extensively on various Android devices (API 29-34) and different OEM skins.
8.  **Battery Optimization:** Review and fine-tune BLE scan/advertising parameters and connection management in `BluetoothMeshService` for optimal battery life.
9.  **Review ProGuard Rules:** Once dependencies like BouncyCastle are fully used, ensure ProGuard rules are adequate for release builds.

This `README.md` provides a snapshot of the project's state and direction. It will be updated as development continues.
