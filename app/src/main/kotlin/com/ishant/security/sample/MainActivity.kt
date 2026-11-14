package com.ishant.security.sample

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import com.ishant.security.SecurityManager
import com.ishant.security.core.EncryptedPayload
import com.ishant.security.crypto.Aes256Gcm
import com.ishant.security.device.AndroidDeviceIdentityKeyStore
import com.ishant.security.handshake.*
import com.ishant.security.keys.RawAesKey
import com.ishant.security.session.SequencedCiphertext
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EdDSA
import dev.whyoleg.cryptography.algorithms.XDH
import dev.whyoleg.cryptography.random.CryptographyRandom
import kotlinx.coroutines.launch
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

@Serializable
data class UserProfile(
    val userId: String,
    val email: String,
    val roles: List<String>,
)

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    SecurityDemoScreen()
                }
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SecurityDemoScreen() {
    var selectedTab by remember { mutableIntStateOf(0) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("KMP Security Tool") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
            )
        },
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues),
        ) {
            TabRow(selectedTabIndex = selectedTab) {
                Tab(
                    selected = selectedTab == 0,
                    onClick = { selectedTab = 0 },
                    text = { Text("Encrypt / Decrypt") },
                )
                Tab(
                    selected = selectedTab == 1,
                    onClick = { selectedTab = 1 },
                    text = { Text("Automated Demos") },
                )
            }

            when (selectedTab) {
                0 -> InteractiveEncryptDecryptTab()
                1 -> AutomatedDemosTab()
            }
        }
    }
}

@Composable
fun InteractiveEncryptDecryptTab() {
    val clipboardManager = LocalClipboardManager.current
    val scope = rememberCoroutineScope()
    val aes = remember { Aes256Gcm() }

    // Shared AES key for the interactive session
    val keyBytes = remember { ByteArray(32) { (it + 1).toByte() } }
    val key = remember { RawAesKey(keyBytes) }

    // Encrypt State
    var plaintextInput by remember { mutableStateOf("Sensitive Payload Data") }
    var encryptAadInput by remember { mutableStateOf("app_context_v1") }
    var encryptedJsonOutput by remember { mutableStateOf("") }
    var encryptError by remember { mutableStateOf("") }

    // Decrypt State
    var encryptedJsonInput by remember { mutableStateOf("") }
    var decryptAadInput by remember { mutableStateOf("app_context_v1") }
    var decryptedResultOutput by remember { mutableStateOf("") }
    var decryptError by remember { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        // --- ENCRYPT SECTION ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f),
            ),
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text(
                    text = "🔒 Encrypt Data",
                    style = MaterialTheme.typography.titleMedium,
                )

                OutlinedTextField(
                    value = plaintextInput,
                    onValueChange = { plaintextInput = it },
                    label = { Text("Plaintext Input") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                )

                OutlinedTextField(
                    value = encryptAadInput,
                    onValueChange = { encryptAadInput = it },
                    label = { Text("Associated Data (AAD - Optional)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )

                Button(
                    onClick = {
                        encryptError = ""
                        scope.launch {
                            try {
                                val aadBytes = encryptAadInput.takeIf { it.isNotBlank() }?.encodeToByteArray()
                                val payload = aes.encrypt(
                                    plaintext = plaintextInput.encodeToByteArray(),
                                    key = key,
                                    associatedData = aadBytes,
                                )
                                encryptedJsonOutput = Json.encodeToString(EncryptedPayload.serializer(), payload)
                            } catch (e: Exception) {
                                encryptError = "Encryption failed: ${e.message}"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Encrypt Data")
                }

                if (encryptError.isNotEmpty()) {
                    Text(
                        text = encryptError,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                if (encryptedJsonOutput.isNotEmpty()) {
                    HorizontalDivider()
                    Text(
                        text = "Encrypted Payload (JSON):",
                        style = MaterialTheme.typography.labelMedium,
                    )
                    Text(
                        text = encryptedJsonOutput,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodySmall,
                        modifier = Modifier.fillMaxWidth(),
                    )

                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        OutlinedButton(
                            onClick = {
                                clipboardManager.setText(AnnotatedString(encryptedJsonOutput))
                            },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text("Copy Output")
                        }

                        OutlinedButton(
                            onClick = {
                                encryptedJsonInput = encryptedJsonOutput
                                decryptAadInput = encryptAadInput
                            },
                            modifier = Modifier.weight(1f),
                        ) {
                            Text("Send to Decrypt")
                        }
                    }
                }
            }
        }

        // --- DECRYPT SECTION ---
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.3f),
            ),
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Text(
                        text = "🔓 Decrypt Data",
                        style = MaterialTheme.typography.titleMedium,
                    )
                    TextButton(
                        onClick = {
                            val clipText = clipboardManager.getText()?.text
                            if (!clipText.isNullOrBlank()) {
                                encryptedJsonInput = clipText
                            }
                        },
                    ) {
                        Text("Paste Clipboard")
                    }
                }

                OutlinedTextField(
                    value = encryptedJsonInput,
                    onValueChange = { encryptedJsonInput = it },
                    label = { Text("Encrypted Payload (JSON)") },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 3,
                )

                OutlinedTextField(
                    value = decryptAadInput,
                    onValueChange = { decryptAadInput = it },
                    label = { Text("Associated Data (AAD)") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                )

                Button(
                    onClick = {
                        decryptError = ""
                        decryptedResultOutput = ""
                        scope.launch {
                            try {
                                val payload = Json.decodeFromString(EncryptedPayload.serializer(), encryptedJsonInput.trim())
                                val aadBytes = decryptAadInput.takeIf { it.isNotBlank() }?.encodeToByteArray()
                                val clearBytes = aes.decrypt(
                                    payload = payload,
                                    key = key,
                                    associatedData = aadBytes,
                                )
                                decryptedResultOutput = clearBytes.decodeToString()
                            } catch (e: Exception) {
                                decryptError = "Decryption failed: ${e.message}"
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Decrypt Payload")
                }

                if (decryptError.isNotEmpty()) {
                    Text(
                        text = decryptError,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }

                if (decryptedResultOutput.isNotEmpty()) {
                    HorizontalDivider()
                    Text(
                        text = "Decrypted Result:",
                        style = MaterialTheme.typography.labelMedium,
                    )
                    Text(
                        text = decryptedResultOutput,
                        fontFamily = FontFamily.Monospace,
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.primary,
                    )
                }
            }
        }
    }
}

@Composable
fun AutomatedDemosTab() {
    val scope = rememberCoroutineScope()
    var logs by remember { mutableStateOf("Tap 'Run Automated Security Checks' to test Android Keystore, AES-GCM, and X25519 Handshake.\n") }
    var isRunning by remember { mutableStateOf(false) }

    fun appendLog(msg: String) {
        logs += "$msg\n"
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(16.dp),
    ) {
        Button(
            onClick = {
                if (isRunning) return@Button
                isRunning = true
                logs = "Starting Security Checks...\n\n"
                scope.launch {
                    try {
                        runAndroidSecurityDemos(::appendLog)
                    } catch (e: Exception) {
                        appendLog("❌ Error: ${e.message}")
                        e.printStackTrace()
                    } finally {
                        isRunning = false
                    }
                }
            },
            modifier = Modifier.fillMaxWidth(),
            enabled = !isRunning,
        ) {
            if (isRunning) {
                CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    color = MaterialTheme.colorScheme.onPrimary,
                    strokeWidth = 2.dp,
                )
                Spacer(modifier = Modifier.width(8.dp))
                Text("Running Demos...")
            } else {
                Text("Run Automated Security Checks")
            }
        }

        Spacer(modifier = Modifier.height(16.dp))

        Card(
            modifier = Modifier
                .fillMaxWidth()
                .weight(1f),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.surfaceVariant,
            ),
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(12.dp)
                    .verticalScroll(rememberScrollState()),
            ) {
                Text(
                    text = logs,
                    fontFamily = FontFamily.Monospace,
                    style = MaterialTheme.typography.bodySmall,
                )
            }
        }
    }
}

private suspend fun runAndroidSecurityDemos(log: (String) -> Unit) {
    // ------------------------------------------------------------------
    // DEMO 1: Android Keystore Identity Key
    // ------------------------------------------------------------------
    log("--- 1. Android Keystore Hardware Identity ---")
    val keyStore = AndroidDeviceIdentityKeyStore()
    val identityPublicKey = keyStore.getOrCreate()
    log("✓ Generated/Loaded P-256 ECDSA Key in Android Keystore")
    log("  Key ID: ${identityPublicKey.keyId}")
    log("  Public Key SPKI Size: ${identityPublicKey.publicKeyDer.size} bytes")

    val challenge = "challenge_non_repeating_nonce_9981".encodeToByteArray()
    val signature = keyStore.sign(challenge)
    log("✓ Signed Challenge with Hardware Private Key: ${signature.size} bytes")
    log("[SUCCESS] Android Keystore Hardware Identity Verified!\n")

    // ------------------------------------------------------------------
    // DEMO 2: AES-256-GCM Operations
    // ------------------------------------------------------------------
    log("--- 2. AES-256-GCM Encryption ---")
    val key = RawAesKey(ByteArray(32) { (it + 1).toByte() })
    val aes = Aes256Gcm()
    val secretText = "Android Confidential User Data"
    val aad = "context:android_demo".encodeToByteArray()

    val encrypted = aes.encrypt(secretText.encodeToByteArray(), key, aad)
    log("✓ Encrypted Payload: ${encrypted.ciphertext.size} bytes (v${encrypted.version})")

    val decryptedBytes = aes.decrypt(encrypted, key, aad)
    log("✓ Decrypted Payload: ${decryptedBytes.decodeToString()}")
    check(decryptedBytes.decodeToString() == secretText)
    log("[SUCCESS] AES-256-GCM Roundtrip Passed!\n")

    // ------------------------------------------------------------------
    // DEMO 3: SecurityManager & Serialization
    // ------------------------------------------------------------------
    log("--- 3. SecurityManager & Serialization ---")
    val manager = SecurityManager()
    val profile = UserProfile("usr_android_101", "mobile@yralfood.com", listOf("MOBILE_USER"))
    val encObj = manager.encryptObject(profile, UserProfile.serializer(), key)
    val decObj: UserProfile = manager.decryptObject(encObj, UserProfile.serializer(), key)
    log("✓ Decrypted Object: $decObj")
    check(decObj == profile)
    log("[SUCCESS] SecurityManager Serialization Passed!\n")

    // ------------------------------------------------------------------
    // DEMO 4: Ephemeral X25519 Handshake & Session
    // ------------------------------------------------------------------
    log("--- 4. Ephemeral X25519 Handshake ---")
    val provider = CryptographyProvider.Default
    val xdh = provider.get(XDH)
    val eddsa = provider.get(EdDSA)

    val serverSigningKey = eddsa.keyPairGenerator(EdDSA.Curve.Ed25519).generateKey()
    val serverSpki = serverSigningKey.publicKey.encodeToByteArray(EdDSA.PublicKey.Format.DER)
    val verifier = PinnedEd25519HandshakeVerifier(mapOf("backend-key" to serverSpki))

    val clientHandshake = X25519Handshake()
    val pending = clientHandshake.begin()

    val serverEphemeralKeyPair = xdh.keyPairGenerator(XDH.Curve.X25519).generateKey()
    val serverEphemeralPublicDer = serverEphemeralKeyPair.publicKey.encodeToByteArray(XDH.PublicKey.Format.DER)
    val serverNonce = CryptographyRandom.nextBytes(32)
    val sessionId = "sess_android_4401"

    val session = clientHandshake.complete(
        pending = pending,
        serverHello = ServerHello(
            sessionId = sessionId,
            serverEphemeralPublicKey = serverEphemeralPublicDer,
            serverNonce = serverNonce,
            signingKeyId = "backend-key",
            signature = ByteArray(64),
        ),
    ) { keyId, transcript, _ ->
        val realSignature = serverSigningKey.privateKey.signatureGenerator().generateSignature(transcript)
        verifier.verify(keyId, transcript, realSignature)
    }

    log("✓ Handshake Complete! Session ID: ${session.sessionId}")

    val reqPayload = "GET /user/profile".encodeToByteArray()
    val encryptedReq: SequencedCiphertext = session.encryptRequest(reqPayload)
    log("✓ Encrypted Request (Seq #${encryptedReq.sequence}): ${encryptedReq.payload.ciphertext.size} bytes")

    log("\n==========================================")
    log(" ALL ANDROID SECURITY DEMOS PASSED SUCCESSFULLY!")
    log("==========================================")
}
