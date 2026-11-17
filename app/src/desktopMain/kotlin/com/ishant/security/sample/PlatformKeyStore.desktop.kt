package com.ishant.security.sample

import com.ishant.security.device.DeviceIdentityKeyStore
import com.ishant.security.device.JvmDeviceIdentityKeyStore

actual fun getPlatformDeviceIdentityKeyStore(): DeviceIdentityKeyStore? = JvmDeviceIdentityKeyStore()
actual val platformName: String = "Desktop"
