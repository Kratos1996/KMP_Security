package com.ishant.security.sample

import com.ishant.security.device.DeviceIdentityKeyStore

expect fun getPlatformDeviceIdentityKeyStore(): DeviceIdentityKeyStore?
expect val platformName: String
