package com.ishant.security.sample

import com.ishant.security.device.AndroidDeviceIdentityKeyStore
import com.ishant.security.device.DeviceIdentityKeyStore

actual fun getPlatformDeviceIdentityKeyStore(): DeviceIdentityKeyStore? = AndroidDeviceIdentityKeyStore()
actual val platformName: String = "Android"
