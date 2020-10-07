/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package android.system.keystore2;
/**
 * `tag` indicates which of the other fields used. It has one
 * of the values of android.hardware.keymint.Tag which have associated
 * types. Once the KeyMint AIDL spec has landed, this interface
 * will use android.hardware.keymint.KeyParameter instead of the this
 * parcelable, and this whole file will go away.
 */
@VintfStability
parcelable KeyParameter {
    int tag;
    boolean boolValue;
    int integer;
    long longInteger;
    long dateTime;
    @nullable byte[] blob;
}
