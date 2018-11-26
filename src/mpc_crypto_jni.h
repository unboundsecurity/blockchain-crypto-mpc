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

#pragma once

#include <jni.h>

extern "C"
{

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved);
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved);

JNIEXPORT void JNICALL Java_com_unboundTech_mpc_Native_freeShare(JNIEnv *, jclass, jlong share_handle);
JNIEXPORT void JNICALL Java_com_unboundTech_mpc_Native_freeContext(JNIEnv *, jclass, jlong context_handle);
JNIEXPORT void JNICALL Java_com_unboundTech_mpc_Native_freeMessage(JNIEnv *, jclass, jlong message_handle);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_shareToBuf(JNIEnv *, jclass, jlong share_handle, jbyteArray j_out, jobject j_out_size);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_contextToBuf(JNIEnv *, jclass, jlong context_handle, jbyteArray j_out, jobject j_out_size);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_messageToBuf(JNIEnv *, jclass, jlong message_handle, jbyteArray j_out, jobject j_out_size);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_shareFromBuf(JNIEnv *, jclass, jbyteArray j_in, jobject j_out_share_handle);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_contextFromBuf(JNIEnv *, jclass, jbyteArray j_in, jobject j_out_context_handle);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_messageFromBuf(JNIEnv *, jclass, jbyteArray j_in, jobject j_out_message_handle);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_shareInfo(JNIEnv *, jclass, jlong share_handle, jobject j_out);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_contextInfo(JNIEnv *, jclass, jlong context_handle, jobject j_out);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_messageInfo(JNIEnv *, jclass, jlong message_handle, jobject j_out);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_step(JNIEnv *, jclass, jlong context_handle, jlong in_message_handle, jobject j_out_message, jobject j_out_flags);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getShare(JNIEnv *, jclass, jlong context_handle, jobject j_out_share);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initRefreshKey(JNIEnv *, jclass, jint peer, jlong share_handle, jobject j_out_context);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getEddsaPublic(JNIEnv *, jclass, jlong share_handle, jbyteArray j_out); // 32 bytes length
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultEddsaSign(JNIEnv *, jclass, jlong context_handle, jbyteArray j_out); // 64 bytes length
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initGenerateEddsaKey(JNIEnv *, jclass, jint peer, jobject j_out_context);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initEddsaSign(JNIEnv *, jclass, jint peer, jlong share_handle, jbyteArray j_in, jboolean refresh, jobject j_out_context);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_verifyEddsa(JNIEnv *, jclass, jbyteArray j_pub_key, jbyteArray j_in, jbyteArray j_signature); // |pub_key|=32, |signature|=64

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getEcdsaPublic(JNIEnv *, jclass, jlong share_handle, jbyteArray j_out, jobject j_out_size);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initGenerateEcdsaKey(JNIEnv *, jclass, jint peer, jobject j_out_context);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initEcdsaSign(JNIEnv *, jclass, jint peer, jlong share_handle, jbyteArray j_in, jboolean refresh, jobject j_out_context);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultEcdsaSign(JNIEnv *, jclass, jlong context_handle, jbyteArray j_out, jobject j_out_size);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_verifyEcdsa(JNIEnv *, jclass, jbyteArray j_pub_key, jbyteArray j_in, jbyteArray j_signature);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initGenerateGenericSecret(JNIEnv *, jclass, jint peer, jint bits, jobject j_out_context);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initImportGenericSecret(JNIEnv *, jclass, jint peer, jbyteArray j_key, jobject j_out_context);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initDeriveBIP32(JNIEnv *, jclass, jint peer, jlong share_handle, jboolean hardened, jint index, jobject j_out_context);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultDeriveBIP32(JNIEnv *,  jclass, jlong context_handle, jobject j_out_share);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getBIP32Info(JNIEnv *, jclass, jlong share_handle, jobject j_bip32_info);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_serializePubBIP32(JNIEnv *, jclass, jlong share_handle, jcharArray j_out, jobject j_out_size);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initBackupEcdsaKey(JNIEnv *, jclass, jint peer, jlong share_handle, jbyteArray j_pub_backup_key, jobject j_out_context);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultBackupEcdsaKey(JNIEnv *, jclass, jlong context_handle, jbyteArray j_out, jobject j_out_size);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_verifyEcdsaBackupKey(JNIEnv *, jclass, jbyteArray j_pub_backup_key, jbyteArray j_pub_key, jbyteArray j_backup); 
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_restoreEcdsaKey(JNIEnv *, jclass, jbyteArray j_prv_backup_key, jbyteArray j_pub_key, jbyteArray j_backup, jbyteArray j_out, jobject j_out_size);

JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_initBackupEddsaKey(JNIEnv *, jclass, jint peer, jlong share_handle, jbyteArray j_pub_backup_key, jobject j_out_context);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_getResultBackupEddsaKey(JNIEnv *, jclass, jlong context_handle, jbyteArray j_out, jobject j_out_size);
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_verifyEddsaBackupKey(JNIEnv *, jclass, jbyteArray j_pub_backup_key, jbyteArray j_pub_key, jbyteArray j_backup); 
JNIEXPORT jint JNICALL Java_com_unboundTech_mpc_Native_restoreEddsaKey(JNIEnv *, jclass, jbyteArray j_prv_backup_key, jbyteArray j_pub_key, jbyteArray j_backup, jbyteArray j_out);  // |out|=32


}