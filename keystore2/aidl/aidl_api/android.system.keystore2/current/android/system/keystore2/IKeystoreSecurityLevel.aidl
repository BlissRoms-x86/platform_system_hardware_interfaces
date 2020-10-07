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
  android.system.keystore2.IKeystoreOperation create(in android.system.keystore2.KeyDescriptor key, in android.system.keystore2.KeyParameter[] operationParameters, in boolean forced, out @nullable android.system.keystore2.OperationChallenge challenge);
  void generateKey(in android.system.keystore2.KeyDescriptor key, in android.system.keystore2.KeyParameter[] params, in byte[] entropy, out android.system.keystore2.KeyDescriptor resultKey, out @nullable android.system.keystore2.Certificate publicCert, out @nullable android.system.keystore2.CertificateChain certificateChain);
  void importKey(in android.system.keystore2.KeyDescriptor key, in android.system.keystore2.KeyParameter[] params, in byte[] keyData, out android.system.keystore2.KeyDescriptor resultKey, out @nullable android.system.keystore2.Certificate publicCert, out @nullable android.system.keystore2.CertificateChain certificateChain);
  void importWrappedKey(in android.system.keystore2.KeyDescriptor key, in android.system.keystore2.KeyDescriptor wrappingKey, in @nullable byte[] maskingKey, in android.system.keystore2.KeyParameter[] params, in android.system.keystore2.AuthenticatorSpec[] authenticators, out android.system.keystore2.KeyDescriptor resultKey, out @nullable android.system.keystore2.Certificate publicCert, out @nullable android.system.keystore2.CertificateChain certificateChain);
}
