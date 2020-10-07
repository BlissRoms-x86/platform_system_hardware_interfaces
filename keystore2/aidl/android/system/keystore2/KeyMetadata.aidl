/*
 * Copyright 2020, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.system.keystore2;

import android.hardware.keymint.SecurityLevel;
import android.system.keystore2.Authorization;
import android.system.keystore2.KeyDescriptor;

/**
 * Metadata of a key entry including the key characteristics `authorizations`
 * security level `securityLevel` and a key id based key descriptor.
 * See KeyDescriptor.aidl for the benefits of key id based key descriptor usage.
 */
@VintfStability
parcelable KeyMetadata {
    KeyDescriptor key;
    SecurityLevel securityLevel;
    Authorization[] authorizations;
}