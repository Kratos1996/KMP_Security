package com.ishant.security.sample

import com.ishant.security.device.DeviceIdentityKeyStore
import com.ishant.security.device.IosDeviceIdentityKeyStore

actual fun getPlatformDeviceIdentityKeyStore(): DeviceIdentityKeyStore? = IosDeviceIdentityKeyStore()
actual val platformName: String = "iOS"
