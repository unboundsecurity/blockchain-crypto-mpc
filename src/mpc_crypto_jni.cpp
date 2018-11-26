/*
 *     NOTICE
 *
 *     The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
 *     If you choose to receive it under the GPL v.3 license, the following applies:
 *     Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
 *     
 *     Copyright (C) 2018, Unbound Tech Ltd. 
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 * 
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 * 
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "precompiled.h"

#ifndef MPC_CRYPTO_NO_JNI

#include "mpc_crypto_jni.h"
#include "jni_helpers.h"
#include "mpc_crypto.h"
#include "crypto.h"

static jclass jclass_IntRef = nullptr;
static jfieldID jfield_IntRef_value = nullptr;

static jclass jclass_Message = nullptr;
static jfieldID jfield_Message_handle = nullptr;

static jclass jclass_Context = nullptr;
static jfieldID jfield_Context_handle = nullptr;

static jclass jclass_Share = nullptr;
static jfieldID jfield_Share_handle = nullptr;

static jclass jclass_Message_Info = nullptr;
static jfieldID jfield_Message_Info_contextUID = nullptr;
static jfieldID jfield_Message_Info_shareUID = nullptr;
static jfieldID jfield_Message_Info_srcPeer = nullptr;
static jfieldID jfield_Message_Info_dstPeer = nullptr;

static jclass jclass_Context_Info = nullptr;
static jfieldID jfield_Context_Info_UID = nullptr;
static jfieldID jfield_Context_Info_shareUID = nullptr;
static jfieldID jfield_Context_Info_peer = nullptr;

static jclass jclass_Share_Info = nullptr;
static jfieldID jfield_Share_Info_UID = nullptr;
static jfieldID jfield_Share_Info_type = nullptr;

static jclass jclass_BIP32_Info = nullptr;
static jfieldID jfield_BIP32_Info_hardened = nullptr;
static jfieldID jfield_BIP32_Info_level = nullptr;
static jfieldID jfield_BIP32_Info_childNumber = nullptr;
static jfieldID jfield_BIP32_Info_parentFingerprint = nullptr;
static jfieldID jfield_BIP32_Info_chainCode = nullptr;


JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
  if (!vm)
  {
    return -1;
  }

  JNIEnv* env = nullptr;
  if (vm->GetEnv((void**)&env, JNI_VERSION_1_2) != JNI_OK) 
  {
    return -1;
  }

  jclass c;

  c = env->FindClass("com/unboundTech/mpc/Native$IntRef");                                              if (!c) return -1;
  jclass_IntRef = (jclass)env->NewGlobalRef(c);                                                         if (!jclass_IntRef) return -1;
  jfield_IntRef_value = env->GetFieldID(jclass_IntRef, "value", "I");                                   if (!jfield_IntRef_value) return -1;
                                                                                                        
  c = env->FindClass("com/unboundTech/mpc/Message");                                                    if (!c) return -1;
  jclass_Message = (jclass)env->NewGlobalRef(c);                                                        if (!jclass_Message) return -1;
  jfield_Message_handle = env->GetFieldID(jclass_Message, "handle", "J");                               if (!jfield_Message_handle) return -1;
                                                                                                        
  c = env->FindClass("com/unboundTech/mpc/Context");                                                    if (!c) return -1;
  jclass_Context = (jclass)env->NewGlobalRef(c);                                                        if (!jclass_Context) return -1;
  jfield_Context_handle = env->GetFieldID(jclass_Context, "handle", "J");                               if (!jfield_Context_handle) return -1;
                                                                                                        
  c = env->FindClass("com/unboundTech/mpc/Share");                                                      if (!c) return -1;
  jclass_Share = (jclass)env->NewGlobalRef(c);                                                          if (!jclass_Share) return -1;
  jfield_Share_handle = env->GetFieldID(jclass_Share, "handle", "J");                                   if (!jfield_Share_handle) return -1;
                                                                                                      
  c = env->FindClass("com/unboundTech/mpc/Message$Info");                                               if (!c) return -1;
  jclass_Message_Info = (jclass)env->NewGlobalRef(c);                                                   if (!jclass_Message_Info) return -1;
  jfield_Message_Info_contextUID = env->GetFieldID(jclass_Message_Info, "contextUID", "J");             if (!jfield_Message_Info_contextUID) return -1;
  jfield_Message_Info_shareUID   = env->GetFieldID(jclass_Message_Info, "shareUID", "J");               if (!jfield_Message_Info_shareUID) return -1;
  jfield_Message_Info_srcPeer    = env->GetFieldID(jclass_Message_Info, "srcPeer", "I");                if (!jfield_Message_Info_srcPeer) return -1;
  jfield_Message_Info_dstPeer    = env->GetFieldID(jclass_Message_Info, "dstPeer", "I");                if (!jfield_Message_Info_dstPeer) return -1;

  c = env->FindClass("com/unboundTech/mpc/Context$Info");                                               if (!c) return -1;
  jclass_Context_Info = (jclass)env->NewGlobalRef(c);                                                   if (!jclass_Context_Info) return -1;
  jfield_Context_Info_UID      = env->GetFieldID(jclass_Context_Info, "UID", "J");                      if (!jfield_Context_Info_UID) return -1;
  jfield_Context_Info_shareUID = env->GetFieldID(jclass_Context_Info, "shareUID", "J");                 if (!jfield_Context_Info_shareUID) return -1;
  jfield_Context_Info_peer     = env->GetFieldID(jclass_Context_Info, "peer", "I");                     if (!jfield_Context_Info_peer) return -1;

  c = env->FindClass("com/unboundTech/mpc/Share$Info");                                                 if (!c) return -1;
  jclass_Share_Info = (jclass)env->NewGlobalRef(c);                                                     if (!jclass_Share_Info) return -1;
  jfield_Share_Info_UID  = env->GetFieldID(jclass_Share_Info, "UID", "J");                              if (!jfield_Share_Info_UID) return -1;
  jfield_Share_Info_type = env->GetFieldID(jclass_Share_Info, "type", "I");                             if (!jfield_Share_Info_type) return -1;

  c = env->FindClass("com/unboundTech/mpc/BIP32Info");                                                  if (!c) return -1;
  jclass_BIP32_Info = (jclass)env->NewGlobalRef(c);                                                     if (!jclass_BIP32_Info) return -1;
  jfield_BIP32_Info_hardened          = env->GetFieldID(jclass_BIP32_Info, "hardened", "Z");            if (!jfield_BIP32_Info_hardened) return -1;
  jfield_BIP32_Info_level             = env->GetFieldID(jclass_BIP32_Info, "level", "B");               if (!jfield_BIP32_Info_level) return -1;
  jfield_BIP32_Info_childNumber       = env->GetFieldID(jclass_BIP32_Info, "childNumber", "I");         if (!jfield_BIP32_Info_childNumber) return -1;
  jfield_BIP32_Info_parentFingerprint = env->GetFieldID(jclass_BIP32_Info, "parentFingerprint", "I");   if (!jfield_BIP32_Info_parentFingerprint) return -1;
  jfield_BIP32_Info_chainCode         = env->GetFieldID(jclass_BIP32_Info, "chainCode", "[B");          if (!jfield_BIP32_Info_chainCode) return -1;

  return JNI_VERSION_1_2;
}

JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
  if (!vm)
  {
    return;
  }

  JNIEnv* env = nullptr;
  if (vm->GetEnv((void**)&env, JNI_VERSION_1_2) != JNI_OK) 
  {
    return ;
  }

  env->DeleteGlobalRef(jclass_IntRef);
  env->DeleteGlobalRef(jclass_Message);
  env->DeleteGlobalRef(jclass_Context);
  env->DeleteGlobalRef(jclass_Share);
  env->DeleteGlobalRef(jclass_Message_Info);
  env->DeleteGlobalRef(jclass_Context_Info);
  env->DeleteGlobalRef(jclass_Share_Info);
  env->DeleteGlobalRef(jclass_BIP32_Info);
}


static void set_int_ref(JNIEnv* env, jobject object, int value)
{
  env->SetIntField(object, jfield_IntRef_value, value);
}

static void set_message_handle(JNIEnv* env, jobject object, MPCCryptoMessage* message)
{
  env->SetLongField(object, jfield_Message_handle, (jlong)(uintptr_t)message);
}

static void set_context_handle(JNIEnv* env, jobject object, MPCCryptoContext* context)
{
  env->SetLongField(object, jfield_Context_handle, (jlong)(uintptr_t)context);
}

static void set_share_handle(JNIEnv* env, jobject object, MPCCryptoShare* share)
{
  env->SetLongField(object, jfield_Share_handle, (jlong)(uintptr_t)share);
}

JNIEXPORT void JNICALL Java_com_unboundTech_mpc_Native_freeShare(JNIEnv *, jclass, jlong share_handle)
{
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  MPCCrypto_freeShare(share);
}

JNIEXPORT void JNICALL Java_com_unboundTech_mpc_Native_freeContext(JNIEnv *, jclass, jlong context_handle)
{
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;
  MPCCrypto_freeContext(context);
}

JNIEXPORT void JNICALL Java_com_unboundTech_mpc_Native_freeMessage(JNIEnv *, jclass, jlong message_handle)
{
  MPCCryptoMessage* message = (MPCCryptoMessage*)(uintptr_t)message_handle;
  MPCCrypto_freeMessage(message);
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_shareToBuf(JNIEnv *env, jclass, jlong share_handle, jbyteArray j_out, jobject j_out_size)
{
  error_t rv = 0;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  ub::jni_out_buf_t out(env, j_out);

  rv = MPCCrypto_shareToBuf(share, out.data, &out.size);
  if (j_out_size) set_int_ref(env, j_out_size, out.size);
  if (rv==0) out.save();
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_contextToBuf(JNIEnv *env, jclass, jlong context_handle, jbyteArray j_out, jobject j_out_size)
{
  error_t rv = 0;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;

  ub::jni_out_buf_t out(env, j_out);
  rv = MPCCrypto_contextToBuf(context, out.data, &out.size);
  if (j_out_size) set_int_ref(env, j_out_size, out.size);
  if (rv==0) out.save();

  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_messageToBuf(JNIEnv *env, jclass, jlong message_handle, jbyteArray j_out, jobject j_out_size)
{
  error_t rv = 0;
  MPCCryptoMessage* message = (MPCCryptoMessage*)(uintptr_t)message_handle;

  ub::jni_out_buf_t out(env, j_out);
  rv = MPCCrypto_messageToBuf(message, out.data, &out.size);
  if (j_out_size) set_int_ref(env, j_out_size, out.size);
  if (rv==0) out.save();
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_shareFromBuf(JNIEnv *env, jclass, jbyteArray j_in, jobject j_out_share_handle)
{
  error_t rv = 0;
  ub::jni_in_buf_t in(env, j_in);
  MPCCryptoShare* share = nullptr;
  if (rv = MPCCrypto_shareFromBuf(in.data, in.size, &share)) return rv;
  set_share_handle(env, j_out_share_handle, share);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_contextFromBuf(JNIEnv *env, jclass, jbyteArray j_in, jobject j_out_context_handle)
{
  error_t rv = 0;
  ub::jni_in_buf_t in(env, j_in);
  MPCCryptoContext* context = nullptr;
  if (rv = MPCCrypto_contextFromBuf(in.data, in.size, &context)) return rv;
  set_context_handle(env, j_out_context_handle, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_messageFromBuf(JNIEnv *env, jclass, jbyteArray j_in, jobject j_out_message_handle)
{
  error_t rv = 0;
  ub::jni_in_buf_t in(env, j_in);
  MPCCryptoMessage* message = nullptr;
  if (rv = MPCCrypto_messageFromBuf(in.data, in.size, &message)) return rv;
  set_message_handle(env, j_out_message_handle, message);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_shareInfo(JNIEnv *env, jclass,  jlong share_handle, jobject j_out)
{
  error_t rv = 0;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  mpc_crypto_share_info_t info = {0};
  if (rv = MPCCrypto_shareInfo(share, &info)) return rv;

  env->SetLongField(j_out, jfield_Share_Info_UID,  info.uid);
  env->SetIntField (j_out, jfield_Share_Info_type, info.type);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_contextInfo(JNIEnv *env, jclass, jlong context_handle, jobject j_out)
{
  error_t rv = 0;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;
  mpc_crypto_context_info_t info = {0};
  if (rv = MPCCrypto_contextInfo(context, &info)) return rv;

  env->SetLongField(j_out, jfield_Context_Info_UID,      info.uid);
  env->SetLongField(j_out, jfield_Context_Info_shareUID, info.share_uid);
  env->SetIntField (j_out, jfield_Context_Info_peer,     info.peer);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_messageInfo(JNIEnv *env, jclass, jlong message_handle, jobject j_out)
{
  error_t rv = 0;
  MPCCryptoMessage* message = (MPCCryptoMessage*)(uintptr_t)message_handle;
  mpc_crypto_message_info_t info = {0};
  if (rv = MPCCrypto_messageInfo(message, &info)) return rv;

  env->SetLongField(j_out, jfield_Message_Info_contextUID, info.context_uid);
  env->SetLongField(j_out, jfield_Message_Info_shareUID,   info.share_uid);
  env->SetIntField (j_out, jfield_Message_Info_srcPeer,    info.src_peer);
  env->SetIntField (j_out, jfield_Message_Info_dstPeer,    info.dst_peer);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_step(JNIEnv *env, jclass, jlong context_handle, jlong in_message_handle, jobject j_out_message, jobject j_out_flags)
{
  error_t rv = 0;

  MPCCryptoMessage* in = (MPCCryptoMessage*)(uintptr_t)in_message_handle;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;

  unsigned flags = 0;
  MPCCryptoMessage* out = nullptr;

  if (rv = MPCCrypto_step(context, in, &out, &flags)) return rv;

  set_int_ref(env, j_out_flags, flags);
  set_message_handle(env, j_out_message, out);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getShare(JNIEnv *env, jclass, jlong context_handle, jobject j_out_share)
{
  error_t rv = 0;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;
  MPCCryptoShare* share = nullptr;
  if (rv = MPCCrypto_getShare(context, &share)) return rv;
  
  set_share_handle(env, j_out_share, share);
  return 0;
}


JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initRefreshKey(JNIEnv *env, jclass, jint peer, jlong share_handle, jobject j_out_context)
{
  error_t rv = 0;

  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  MPCCryptoContext* context = nullptr;
  if (rv = MPCCrypto_initRefreshKey(peer, share, &context)) return rv;
  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getEddsaPublic(JNIEnv *env, jclass, jlong share_handle, jbyteArray j_out) // 32 bytes length
{
  error_t rv = 0;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  
  ub::jni_out_buf_t out(env, j_out);
  if (out.size!=32) return ub::error(E_BADARG);
  if (rv = MPCCrypto_getEddsaPublic(share, out.data)) return rv;

  out.save(32);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultEddsaSign(JNIEnv *env, jclass, jlong context_handle, jbyteArray j_out) // 64 bytes length
{
  error_t rv = 0;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;
  
  ub::jni_out_buf_t out(env, j_out);
  if (out.size!=64) return ub::error(E_BADARG);
  if (rv = MPCCrypto_getResultEddsaSign(context, out.data)) return rv;

  out.save(64);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initGenerateEddsaKey(JNIEnv *env, jclass, jint peer, jobject j_out_context)
{
  error_t rv = 0;
  MPCCryptoContext* context = nullptr;
  if (rv = MPCCrypto_initGenerateEddsaKey(peer, &context)) return rv;
  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initEddsaSign(JNIEnv *env, jclass, jint peer, jlong share_handle, jbyteArray j_in, jboolean refresh, jobject j_out_context)
{
  error_t rv = 0;

  MPCCryptoContext* context = nullptr;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  ub::jni_in_buf_t in(env, j_in);

  if (rv = MPCCrypto_initEddsaSign(peer, share, in.data, in.size, refresh?1:0, &context)) return rv;

  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_verifyEddsa(JNIEnv * env, jclass, jbyteArray j_pub_key, jbyteArray j_in, jbyteArray j_signature)
{
  error_t rv = 0;

  ub::jni_in_buf_t in(env, j_in);
  ub::jni_in_buf_t pub_key(env, j_pub_key);
  ub::jni_in_buf_t signature(env, j_signature);

  if (pub_key.size!=32) return rv = ub::error(E_BADARG);
  if (signature.size!=64) return rv = ub::error(E_BADARG);

  return rv = MPCCrypto_verifyEddsa(pub_key.data, in.data, in.size, signature.data);
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getEcdsaPublic(JNIEnv *env, jclass, jlong share_handle, jbyteArray j_out, jobject j_out_size)
{
  error_t rv = 0;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
 
  ub::jni_out_buf_t out(env, j_out);
  rv = MPCCrypto_getEcdsaPublic(share, out.data, &out.size);
  if (j_out_size) set_int_ref(env, j_out_size, out.size);
  if (rv==0) out.save();

  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initGenerateEcdsaKey(JNIEnv *env, jclass, jint peer, jobject j_out_context)
{
  error_t rv = 0;
  MPCCryptoContext* context = nullptr;
  if (rv = MPCCrypto_initGenerateEcdsaKey(peer, &context)) return rv;
  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initEcdsaSign(JNIEnv *env, jclass, jint peer, jlong share_handle, jbyteArray j_in, jboolean refresh, jobject j_out_context)
{
  error_t rv = 0;
  MPCCryptoContext* context = nullptr;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  ub::jni_in_buf_t in(env, j_in);

  if (rv = MPCCrypto_initEcdsaSign(peer, share, in.data, in.size, refresh?1:0, &context)) return rv;

  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultEcdsaSign(JNIEnv *env, jclass, jlong context_handle, jbyteArray j_out, jobject j_out_size) 
{
  error_t rv = 0;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;
  
  ub::jni_out_buf_t out(env, j_out);
  rv = MPCCrypto_getResultEcdsaSign(context, out.data, &out.size);
  if (j_out_size) set_int_ref(env, j_out_size, out.size);
  if (rv==0) out.save();
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_verifyEcdsa(JNIEnv * env, jclass, jbyteArray j_pub_key, jbyteArray j_in, jbyteArray j_signature)
{
  error_t rv = 0;

  ub::jni_in_buf_t in(env, j_in);
  ub::jni_in_buf_t pub_key(env, j_pub_key);
  ub::jni_in_buf_t signature(env, j_signature);

  return rv = MPCCrypto_verifyEcdsa(pub_key.data, pub_key.size, in.data, in.size, signature.data, signature.size);
}



JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initGenerateGenericSecret(JNIEnv *env, jclass, jint peer, jint bits, jobject j_out_context)
{
  error_t rv = 0;
  MPCCryptoContext* context = nullptr;
  if (rv = MPCCrypto_initGenerateGenericSecret(peer, bits, &context)) return rv;
  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initImportGenericSecret(JNIEnv *env, jclass, jint peer, jbyteArray j_key, jobject j_out_context)
{
  error_t rv = 0;
  ub::jni_in_buf_t in(env, j_key);
  MPCCryptoContext* context = nullptr;
  if (rv = MPCCrypto_initImportGenericSecret(peer, in.data, in.size, &context)) return rv;
  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initDeriveBIP32(JNIEnv *env, jclass, jint peer, jlong share_handle, jboolean hardened, jint index, jobject j_out_context)
{
  error_t rv = 0;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  MPCCryptoContext* context = nullptr;
  if (rv = MPCCrypto_initDeriveBIP32(peer, share, hardened ? 1 : 0, index, &context)) return rv;
  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultDeriveBIP32(JNIEnv *env, jclass, jlong context_handle, jobject j_out_share)
{
  error_t rv = 0;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;
  MPCCryptoShare* out_share = nullptr;
  if (rv = MPCCrypto_getResultDeriveBIP32(context, &out_share)) return rv;
  set_share_handle(env, j_out_share, out_share);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getBIP32Info(JNIEnv *env, jclass, jlong share_handle, jobject j_bip32_info)
{
  error_t rv = 0;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  bip32_info_t info = {0};
  if (rv = MPCCrypto_getBIP32Info(share, &info)) return rv;

  env->SetBooleanField(j_bip32_info, jfield_BIP32_Info_hardened,          jboolean(info.hardened ? 1 : 0));
  env->SetByteField   (j_bip32_info, jfield_BIP32_Info_level,             jbyte(info.level));
  env->SetIntField    (j_bip32_info, jfield_BIP32_Info_childNumber,       jint(info.child_number));
  env->SetIntField    (j_bip32_info, jfield_BIP32_Info_parentFingerprint, jint(info.parent_fingerprint));

  jbyteArray j_chain_code = (jbyteArray)env->GetObjectField(j_bip32_info, jfield_BIP32_Info_chainCode);
  env->SetByteArrayRegion(j_chain_code, 0, 32, (jbyte*)info.chain_code);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_serializePubBIP32(JNIEnv *env, jclass, jlong share_handle, jcharArray j_out, jobject j_out_size)
{
  error_t rv = 0;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;

  int str_size = 0;
  rv = MPCCrypto_serializePubBIP32(share, nullptr, &str_size);
  int out_size = str_size-1;

  if (j_out_size) set_int_ref(env, j_out_size, out_size);
  if (rv) return rv;

  if (j_out)
  {
    int out_size_buf = env->GetArrayLength(j_out);
    if (out_size_buf<out_size) return rv = ub::error(E_TOO_SMALL);

    char* chars = new char[str_size];
    jchar* j_chars = new jchar[out_size];

    MPCCrypto_serializePubBIP32(share, chars, &str_size);
    for (int i=0; i<out_size; i++) j_chars[i] = jchar(chars[i]);
    env->SetCharArrayRegion(j_out, 0, out_size, j_chars);

    delete[] chars;
    delete[] j_chars;
  }

  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initBackupEcdsaKey(JNIEnv *env, jclass, jint peer, jlong share_handle, jbyteArray j_pub_backup_key, jobject j_out_context)
{
  error_t rv = 0;
  MPCCryptoContext* context = nullptr;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  ub::jni_in_buf_t pub_backup_key(env, j_pub_backup_key);

  if (rv = MPCCrypto_initBackupEcdsaKey(peer, share, pub_backup_key.data, pub_backup_key.size, &context)) return rv;
  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultBackupEcdsaKey(JNIEnv *env, jclass, jlong context_handle, jbyteArray j_out, jobject j_out_size)
{
  error_t rv = 0;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;
  
  ub::jni_out_buf_t out(env, j_out);
  rv = MPCCrypto_getResultBackupEcdsaKey(context, out.data, &out.size);
  if (j_out_size) set_int_ref(env, j_out_size, out.size);
  if (rv==0) out.save();
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_verifyEcdsaBackupKey(JNIEnv *env, jclass, jbyteArray j_pub_backup_key, jbyteArray j_pub_key, jbyteArray j_backup)
{
  error_t rv = 0;
  ub::jni_in_buf_t pub_backup_key(env, j_pub_backup_key);
  ub::jni_in_buf_t pub_key(env, j_pub_key);
  ub::jni_in_buf_t backup(env, j_backup);

  if (rv = MPCCrypto_verifyEcdsaBackupKey(pub_backup_key.data, pub_backup_key.size, pub_key.data, pub_key.size, backup.data, backup.size)) return rv;
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_restoreEcdsaKey(JNIEnv *env, jclass, jbyteArray j_prv_backup_key, jbyteArray j_pub_key, jbyteArray j_backup, jbyteArray j_out, jobject j_out_size)
{
  error_t rv = 0;
  ub::jni_in_buf_t prv_backup_key(env, j_prv_backup_key);
  ub::jni_in_buf_t backup(env, j_backup);
  ub::jni_in_buf_t pub_key(env, j_pub_key);
  ub::jni_out_buf_t out(env, j_out);

  rv = MPCCrypto_restoreEcdsaKey(prv_backup_key.data, prv_backup_key.size, pub_key.data, pub_key.size, backup.data, backup.size, out.data, &out.size);
  if (j_out_size) set_int_ref(env, j_out_size, out.size);
  if (rv==0) out.save();

  return rv;
}


JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initBackupEddsaKey(JNIEnv *env, jclass, jint peer, jlong share_handle, jbyteArray j_pub_backup_key, jobject j_out_context)
{
  error_t rv = 0;
  MPCCryptoContext* context = nullptr;
  MPCCryptoShare* share = (MPCCryptoShare*)(uintptr_t)share_handle;
  ub::jni_in_buf_t pub_backup_key(env, j_pub_backup_key);

  if (rv = MPCCrypto_initBackupEddsaKey(peer, share, pub_backup_key.data, pub_backup_key.size, &context)) return rv;
  set_context_handle(env, j_out_context, context);
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultBackupEddsaKey(JNIEnv *env, jclass, jlong context_handle, jbyteArray j_out, jobject j_out_size)
{
  error_t rv = 0;
  MPCCryptoContext* context = (MPCCryptoContext*)(uintptr_t)context_handle;
  
  ub::jni_out_buf_t out(env, j_out);
  rv = MPCCrypto_getResultBackupEddsaKey(context, out.data, &out.size);
  if (j_out_size) set_int_ref(env, j_out_size, out.size);
  if (rv==0) out.save();
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_verifyEddsaBackupKey(JNIEnv *env, jclass, jbyteArray j_pub_backup_key, jbyteArray j_pub_key, jbyteArray j_backup)
{
  error_t rv = 0;
  ub::jni_in_buf_t pub_backup_key(env, j_pub_backup_key);
  ub::jni_in_buf_t pub_key(env, j_pub_key);
  ub::jni_in_buf_t backup(env, j_backup);

  if (pub_key.size!=32) return rv = ub::error(E_BADARG);

  if (rv = MPCCrypto_verifyEddsaBackupKey(pub_backup_key.data, pub_backup_key.size, pub_key.data, backup.data, backup.size)) return rv;
  return 0;
}

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_restoreEddsaKey(JNIEnv *env, jclass, jbyteArray j_prv_backup_key, jbyteArray j_pub_key, jbyteArray j_backup, jbyteArray j_out)  // |out|=32
{
  error_t rv = 0;
  ub::jni_in_buf_t prv_backup_key(env, j_prv_backup_key);
  ub::jni_in_buf_t backup(env, j_backup);
  ub::jni_in_buf_t pub_key(env, j_pub_key);
  ub::jni_out_buf_t out(env, j_out);

  if (pub_key.size!=32) return rv = ub::error(E_BADARG);
  if (out.size!=32) return rv = ub::error(E_BADARG);

  if (rv = MPCCrypto_restoreEddsaKey(prv_backup_key.data, prv_backup_key.size, pub_key.data, backup.data, backup.size, out.data)) return rv;
  out.save();

  return rv;
}

#endif // MPC_CRYPTO_NO_JNI
