package com.ishant.security.device

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import platform.CoreFoundation.CFDataCreate
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFDataRef
import platform.CoreFoundation.CFDictionaryCreateMutable
import platform.CoreFoundation.CFDictionarySetValue
import platform.CoreFoundation.CFErrorGetCode
import platform.CoreFoundation.CFErrorRefVar
import platform.CoreFoundation.CFMutableDictionaryRef
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFTypeRefVar
import platform.CoreFoundation.kCFAllocatorDefault
import platform.CoreFoundation.kCFBooleanTrue
import platform.CoreFoundation.kCFTypeDictionaryKeyCallBacks
import platform.CoreFoundation.kCFTypeDictionaryValueCallBacks
import platform.Security.SecAccessControlCreateWithFlags
import platform.Security.SecItemCopyMatching
import platform.Security.SecItemDelete
import platform.Security.SecKeyCopyExternalRepresentation
import platform.Security.SecKeyCopyPublicKey
import platform.Security.SecKeyCreateRandomKey
import platform.Security.SecKeyCreateSignature
import platform.Security.SecKeyIsAlgorithmSupported
import platform.Security.SecKeyRef
import platform.Security.errSecItemNotFound
import platform.Security.errSecSuccess
import platform.Security.kSecAccessControlPrivateKeyUsage
import platform.Security.kSecAttrAccessControl
import platform.Security.kSecAttrAccessible
import platform.Security.kSecAttrAccessibleWhenUnlockedThisDeviceOnly
import platform.Security.kSecAttrApplicationTag
import platform.Security.kSecAttrIsPermanent
import platform.Security.kSecAttrKeySizeInBits
import platform.Security.kSecAttrKeyType
import platform.Security.kSecAttrKeyTypeECSECPrimeRandom
import platform.Security.kSecAttrTokenID
import platform.Security.kSecAttrTokenIDSecureEnclave
import platform.Security.kSecClass
import platform.Security.kSecClassKey
import platform.Security.kSecPrivateKeyAttrs
import platform.Security.kSecReturnRef
import platform.Security.kSecKeyAlgorithmECDSASignatureMessageX962SHA256
import platform.posix.memcpy

/**
 * iOS installation identity backed exclusively by Secure Enclave.
 *
 * There is deliberately no software-key fallback: devices/simulators without
 * Secure Enclave support fail closed. The P-256 private key is non-exportable.
 */
@OptIn(ExperimentalForeignApi::class)
class IosDeviceIdentityKeyStore(
    private val applicationTag: String = DEFAULT_APPLICATION_TAG
) : DeviceIdentityKeyStore {

    init {
        require(applicationTag.isNotBlank()) { "Keychain application tag cannot be blank" }
    }

    override suspend fun getOrCreate(): DeviceIdentityPublicKey = withContext(Dispatchers.Default) {
        val privateKey = loadPrivateKey() ?: createSecureEnclaveKey()
        try {
            val publicKey = SecKeyCopyPublicKey(privateKey)
                ?: error("Unable to obtain Secure Enclave public key")
            try {
                val point = exportKey(publicKey)
                require(point.size == P256_UNCOMPRESSED_POINT_SIZE && point[0] == 0x04.toByte()) {
                    "Unexpected P-256 public key representation"
                }
                val der = SPKI_P256_PREFIX + point
                DeviceIdentityPublicKey(
                    keyId = der.fingerprintKeyId(),
                    publicKeyDer = der
                )
            } finally {
                CFRelease(publicKey)
            }
        } finally {
            CFRelease(privateKey)
        }
    }

    override suspend fun sign(challenge: ByteArray): ByteArray = withContext(Dispatchers.Default) {
        require(challenge.size in MIN_CHALLENGE_SIZE..MAX_CHALLENGE_SIZE) {
            "Challenge must contain 16..4096 bytes"
        }

        val privateKey = loadPrivateKey()
            ?: error("Secure Enclave identity key does not exist; call getOrCreate first")
        try {
            check(
                SecKeyIsAlgorithmSupported(
                    privateKey,
                    platform.Security.kSecKeyOperationTypeSign,
                    SIGNATURE_ALGORITHM
                )
            ) { "Secure Enclave key does not support ECDSA P-256 signing" }

            withChallengeData(challenge) { data, errorRef ->
                val signature = SecKeyCreateSignature(privateKey, SIGNATURE_ALGORITHM, data, errorRef)
                    ?: error("Secure Enclave signing failed: ${errorRef.pointed?.value?.let { CFErrorGetCode(it) }}")
                try {
                    signature.toByteArray()
                } finally {
                    CFRelease(signature)
                }
            }
        } finally {
            CFRelease(privateKey)
        }
    }

    override suspend fun delete() = withContext(Dispatchers.Default) {
        val query = newDictionary()
        CFDictionarySetValue(query, kSecClass, kSecClassKey)
        val tag = applicationTag.encodeToByteArray().toCFData()
            ?: error("Unable to encode Keychain application tag")
        CFDictionarySetValue(query, kSecAttrApplicationTag, tag)
        CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        try {
            val status = SecItemDelete(query)
            check(status == errSecSuccess || status == errSecItemNotFound) {
                "Secure Enclave key deletion failed: $status"
            }
        } finally {
            CFRelease(tag)
            CFRelease(query)
        }
    }

    private fun loadPrivateKey(): SecKeyRef? = memScoped {
        val query = newDictionary()
        val tag = applicationTag.encodeToByteArray().toCFData()
            ?: error("Unable to encode Keychain application tag")
        CFDictionarySetValue(query, kSecClass, kSecClassKey)
        CFDictionarySetValue(query, kSecAttrApplicationTag, tag)
        CFDictionarySetValue(query, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)
        CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue)
        val result = alloc<CFTypeRefVar>()
        val status = SecItemCopyMatching(query, result.ptr)
        CFRelease(tag)
        CFRelease(query)
        when (status) {
            errSecSuccess -> result.value?.reinterpret()
            errSecItemNotFound -> null
            else -> error("Secure Enclave Keychain lookup failed: $status")
        }
    }

    private fun createSecureEnclaveKey(): SecKeyRef = memScoped {
        val errorRef = alloc<CFErrorRefVar>()
        val tag = applicationTag.encodeToByteArray().toCFData()
            ?: error("Unable to encode Keychain application tag")
        val privateAttributes = newDictionary()
        CFDictionarySetValue(privateAttributes, kSecAttrIsPermanent, kCFBooleanTrue)
        CFDictionarySetValue(privateAttributes, kSecAttrApplicationTag, tag)

        val accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAccessControlPrivateKeyUsage,
            errorRef.ptr
        ) ?: error("Secure Enclave access control unavailable: ${errorRef.value?.let { CFErrorGetCode(it) }}")

        CFDictionarySetValue(privateAttributes, kSecAttrAccessControl, accessControl)
        val attributes = newDictionary()
        CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom)

        val keySize = alloc<platform.posix.int32_tVar>().apply { value = P256_BITS }
        val size = platform.CoreFoundation.CFNumberCreate(
            kCFAllocatorDefault,
            platform.CoreFoundation.kCFNumberIntType,
            keySize.ptr
        ) ?: error("Unable to create key-size attribute")
        CFDictionarySetValue(attributes, kSecAttrKeySizeInBits, size)
        CFDictionarySetValue(attributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave)
        CFDictionarySetValue(attributes, kSecPrivateKeyAttrs, privateAttributes)

        try {
            SecKeyCreateRandomKey(attributes, errorRef.ptr)
                ?: error("Secure Enclave key generation failed: ${errorRef.value?.let { CFErrorGetCode(it) }}")
        } finally {
            CFRelease(attributes)
            CFRelease(privateAttributes)
            CFRelease(accessControl)
            CFRelease(size)
            CFRelease(tag)
        }
    }

    private inline fun <T> withChallengeData(
        bytes: ByteArray,
        block: (CFDataRef?, CPointer<CFErrorRefVar>) -> T
    ): T = memScoped {
        val data = bytes.toCFData() ?: error("Unable to allocate challenge data")
        try {
            block(data, alloc<CFErrorRefVar>().ptr)
        } finally {
            CFRelease(data)
        }
    }

    private fun exportKey(key: SecKeyRef): ByteArray = memScoped {
        val errorRef = alloc<CFErrorRefVar>()
        val data = SecKeyCopyExternalRepresentation(key, errorRef.ptr)
            ?: error("Secure Enclave public key export failed: ${errorRef.value?.let { CFErrorGetCode(it) }}")
        try {
            data.toByteArray()
        } finally {
            CFRelease(data)
        }
    }

    private fun newDictionary(): CFMutableDictionaryRef = CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        0,
        kCFTypeDictionaryKeyCallBacks.ptr,
        kCFTypeDictionaryValueCallBacks.ptr
    ) ?: error("Unable to allocate Keychain query")

    private fun ByteArray.toCFData(): CFDataRef? = usePinned {
        CFDataCreate(kCFAllocatorDefault, it.addressOf(0).reinterpret(), size.convert())
    }

    private fun CFDataRef.toByteArray(): ByteArray {
        val length = CFDataGetLength(this).toInt()
        val bytes = CFDataGetBytePtr(this)
        if (length == 0 || bytes == null) return ByteArray(0)
        return ByteArray(length).apply {
            usePinned { memcpy(it.addressOf(0), bytes, length.convert()) }
        }
    }

    private fun ByteArray.fingerprintKeyId(): String =
        "p256-" + copyOfRange(SPKI_P256_PREFIX.size + 1, SPKI_P256_PREFIX.size + 21)
            .joinToString("") { "%02x".format(it.toInt() and 0xff) }

    private companion object {
        const val DEFAULT_APPLICATION_TAG = "com.ishant.security.device.identity.p256.v1"
        const val P256_BITS = 256
        const val P256_UNCOMPRESSED_POINT_SIZE = 65
        const val MIN_CHALLENGE_SIZE = 16
        const val MAX_CHALLENGE_SIZE = 4096
        val SIGNATURE_ALGORITHM = kSecKeyAlgorithmECDSASignatureMessageX962SHA256
        val SPKI_P256_PREFIX = byteArrayOf(
            0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D,
            0x02, 0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01,
            0x07, 0x03, 0x42, 0x00
        )
    }
}
