# BitChat - Android Port (In Progress)

This project is an Android port of the BitChat application, originally an iOS secure, decentralized, peer-to-peer messaging app using Bluetooth mesh networking.

## Current Status

This port has implemented the core functionalities required for on-device testing. Key features include:
*   **Robust BLE Connectivity:** `BluetoothMeshService` handles scanning, advertising, and GATT operations. It runs as a Foreground Service and includes logic for automatic reconnection with exponential backoff for known peers.
*   **Secure Protocol:** `EncryptionService` (using BouncyCastle) and `BinaryProtocol` handle end-to-end encryption, message signing (Ed25519), compression (LZ4), and data serialization.
*   **Peer & Channel Management:** The application now supports a basic framework for multi-channel communication, including creating channels and persisting the channel list.
*   **UI (Jetpack Compose):** The UI provides a functional chat screen, a channel list placeholder, and a channel creation screen placeholder. It displays detailed BLE status and handles runtime permissions.
*   **Data Persistence:** `DataStorageService` uses Jetpack DataStore and Android Keystore to securely manage user identity, peer public keys, channel information, and message history.

## Architecture Overview (Android)

*   **UI Layer:** Jetpack Compose (`ChatScreen.kt`, `ChannelListScreen.kt`, etc.).
*   **ViewModel Layer:** `ChatViewModel.kt` using Android Architecture Components (`AndroidViewModel`).
*   **Service Layer:** `BluetoothMeshService.kt`, `EncryptionService.kt`, `MessageMetadataService.kt`.
*   **Data Layer:** `DataStorageService.kt`, `MessageRepository.kt`, `ChannelRepository.kt`.
*   **Protocol:** `BitchatProtocol.kt` defining message structures and `BinaryProtocol` for serialization.

---

## Running and Testing the Application

### 1. Running Local Unit Tests

Due to potential limitations in some development environments (like sandboxes), it's crucial to run the unit tests locally to verify the core logic.

1.  **Prerequisites:**
    *   Android Studio (latest stable version recommended).
    *   Java Development Kit (JDK) configured for Android Studio.
2.  **Execution:**
    *   Open the project in Android Studio and wait for Gradle to sync.
    *   **Via Terminal:** Open the Terminal window in Android Studio and run the command:
        ```bash
        ./gradlew testDebugUnitTest
        ```
    *   **Via IDE:** Navigate to a test file in `app/src/test/java/com/example/bitchat/`. Right-click on the class or a specific test method and select "Run ...".
    *   **Verification:** Check the test results in the "Run" window. All tests, especially `EncryptionServiceTest`, `BitchatProtocolTest`, and `CompressionUtilTest`, should pass.

### 2. Guide for E2E Testing on Multiple Devices

This guide outlines the steps to test the peer-to-peer functionality on physical devices.

1.  **Initial Setup:**
    *   Clone the repository: `git clone [URL_DEL_REPO]`
    *   Open the project in the latest stable version of Android Studio.
    *   Enable "Developer Options" and "USB Debugging" on at least two physical Android devices (API 29+).

2.  **Build and Install:**
    *   Connect both devices to your computer via USB.
    *   In Android Studio, select the first device from the device dropdown menu.
    *   Select the `debug` build variant.
    *   Click "Run 'app'" (Shift+F10) to build and install the debug APK on the first device.
    *   Repeat the process for the second device.

3.  **Initial Launch & Permission Granting:**
    *   Open the BitChat app on both devices.
    *   On the first launch, the app will request permissions (Bluetooth, Location, Notifications). **Grant all requested permissions** on both devices.
    *   Verify that Bluetooth is enabled on both devices.

4.  **Verifying Connectivity (using UI and Logcat):**
    *   **UI Feedback:** The top app bar should display a status. Initially, it might show "Scanning" or "Advertising". After a few moments, it should change to "Connected to [Peer]" or similar, and the "Peers" count should be at least 1.
    *   **Logcat Monitoring:**
        *   In Android Studio, open the Logcat window (`View > Tool Windows > Logcat`).
        *   In the device dropdown at the top of Logcat, select one of the test devices. You can open two Logcat tabs to monitor both devices simultaneously.
        *   In the Logcat filter bar, filter by tag to see relevant logs. Useful tags include:
            *   `BTMeshService` (for all BLE operations)
            *   `ChatViewModel` (for UI logic and user actions)
            *   `BitChatProtocol` (for serialization/deserialization)
            *   `BitChatEncrypt` (for crypto operations)
            *   `BitChatDataStore` (for data persistence)
        *   **Look for:** Logs indicating successful advertising, scanning, connection (`onConnectionStateChange`), service discovery, and `Announce` messages being sent and received.

5.  **Testing Secure Messaging:**
    *   On Device A, in the default `#general` channel, type and send a message.
    *   **Verify on Device A:** The message appears instantly in your UI. Check Logcat for logs related to message creation, signing, serialization, and sending via `BluetoothMeshService`.
    *   **Verify on Device B:** The message should appear in the UI within a few seconds. Check Logcat for logs related to data reception, packet deserialization, **successful signature verification**, message deserialization, and UI update.
    *   Repeat the process by sending a message from Device B to Device A.

6.  **Testing Connection Resilience:**
    *   With both devices connected and messaging working, turn off Bluetooth on Device B.
    *   **Verify on Device A:** The UI state should change to "Reconnecting..." or similar. Logcat (`BTMeshService`) should show disconnection events and the start of the reconnection logic (with delays).
    *   Turn Bluetooth back on for Device B.
    *   **Verify:** Device A should automatically reconnect to Device B. The UI state should update to "Connected". Test messaging again to confirm it works.

## ProGuard / R8 Configuration

The project is configured with `minifyEnabled true` for `release` builds. The rules in `app/proguard-rules.pro` are set up to preserve necessary classes for key libraries like BouncyCastle, Gson, and Kotlin Coroutines. Always test release builds thoroughly before distribution.
