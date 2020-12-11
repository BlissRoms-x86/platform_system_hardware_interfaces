///////////////////////////////////////////////////////////////////////////////
// THIS FILE IS IMMUTABLE. DO NOT EDIT IN ANY CASE.                          //
///////////////////////////////////////////////////////////////////////////////

// This file is a snapshot of an AIDL interface (or parcelable). Do not try to
// edit this file. It looks like you are doing that because you have modified
// an AIDL interface in a backward-incompatible way, e.g., deleting a function
// from an interface or a field from a parcelable and it broke the build. That
// breakage is intended.
//
// You must not make a backward incompatible changes to the AIDL files built
// with the aidl_interface module type with versions property set. The module
// type is used to build AIDL files in a way that they can be used across
// independently updatable components of the system. If a device is shipped
// with such a backward incompatible change, it has a high risk of breaking
// later when a module using the interface is updated, e.g., Mainline modules.

package android.system.keystore2;
@VintfStability
interface IKeystoreSecurityLevel {
  android.system.keystore2.CreateOperationResponse createOperation(in android.system.keystore2.KeyDescriptor key, in android.hardware.keymint.KeyParameter[] operationParameters, in boolean forced);
  android.system.keystore2.KeyMetadata generateKey(in android.system.keystore2.KeyDescriptor key, in @nullable android.system.keystore2.KeyDescriptor attestationKey, in android.hardware.keymint.KeyParameter[] params, in int flags, in byte[] entropy);
  android.system.keystore2.KeyMetadata importKey(in android.system.keystore2.KeyDescriptor key, in @nullable android.system.keystore2.KeyDescriptor attestationKey, in android.hardware.keymint.KeyParameter[] params, in int flags, in byte[] keyData);
  android.system.keystore2.KeyMetadata importWrappedKey(in android.system.keystore2.KeyDescriptor key, in android.system.keystore2.KeyDescriptor wrappingKey, in @nullable byte[] maskingKey, in android.hardware.keymint.KeyParameter[] params, in android.system.keystore2.AuthenticatorSpec[] authenticators);
  const int KEY_FLAG_AUTH_BOUND_WITHOUT_CRYPTOGRAPHIC_LSKF_BINDING = 1;
}
