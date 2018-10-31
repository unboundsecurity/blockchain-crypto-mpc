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

#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>

#ifdef MPC_CRYPTO_EXPORTS
#ifdef _WIN32
#define MPCCRYPTO_API __declspec(dllexport)
#else
#define MPCCRYPTO_API __attribute__  ((visibility("default")))
#endif
#else
#define MPCCRYPTO_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct tag_MPCCryptoKey     MPCCryptoShare;
typedef struct tag_MPCCryptoContext MPCCryptoContext;
typedef struct tag_MPCCryptoMessage MPCCryptoMessage;

enum mpc_crypto_key_e : unsigned
{ 
  mpc_none           = 0,

  mpc_eddsa          = 2,
  mpc_ecdsa          = 3,
  mpc_generic_secret = 4, // used for the seed
};

enum mpc_crypto_err_e
{
  MPC_E_BADARG     = 0xff010002, // bad argument
  MPC_E_FORMAT     = 0xff010003, // invalid format
  MPC_E_TOO_SMALL  = 0xff010008, // buffer too small
  MPC_E_CRYPTO     = 0xff040001, // crypto error, process is being tampered
};

typedef struct tag_mpc_crypto_share_info_t
{
  uint64_t         uid;
  mpc_crypto_key_e type;
} mpc_crypto_share_info_t;

typedef struct tag_mpc_crypto_context_info_t
{
  uint64_t uid;
  uint64_t share_uid;
  int      peer;
} mpc_crypto_context_info_t;

typedef struct tag_mpc_crypto_message_info_t
{
  uint64_t context_uid;
  uint64_t share_uid;
  int src_peer;
  int dst_peer;
} mpc_crypto_message_info_t;

typedef struct tag_bip32_info_t
{
  int hardened;
  uint8_t level;
  uint32_t child_number;
  uint32_t parent_fingerprint;
  uint8_t chain_code[32];
} bip32_info_t;


enum mpc_step_flags_e
{
  mpc_protocol_finished = 1,
  mpc_share_changed     = 2, // only sent w/finish
};

// Memory management 
MPCCRYPTO_API void MPCCrypto_freeShare  (MPCCryptoShare* share);
MPCCRYPTO_API void MPCCrypto_freeContext(MPCCryptoContext* context);
MPCCRYPTO_API void MPCCrypto_freeMessage(MPCCryptoMessage* message);

// Serialization
MPCCRYPTO_API int MPCCrypto_shareToBuf  (MPCCryptoShare* share,     uint8_t* out, int* out_size);
MPCCRYPTO_API int MPCCrypto_contextToBuf(MPCCryptoContext* context, uint8_t* out, int* out_size);
MPCCRYPTO_API int MPCCrypto_messageToBuf(MPCCryptoMessage* message, uint8_t* out, int* out_size);

// Deserialization
MPCCRYPTO_API int MPCCrypto_shareFromBuf  (const uint8_t* in, int in_size, MPCCryptoShare** share);
MPCCRYPTO_API int MPCCrypto_contextFromBuf(const uint8_t* in, int in_size, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_messageFromBuf(const uint8_t* in, int in_size, MPCCryptoMessage** message);

// Information
MPCCRYPTO_API int MPCCrypto_shareInfo  (MPCCryptoShare* share,     mpc_crypto_share_info_t*   info);
MPCCRYPTO_API int MPCCrypto_contextInfo(MPCCryptoContext* context, mpc_crypto_context_info_t* info);
MPCCRYPTO_API int MPCCrypto_messageInfo(MPCCryptoMessage* message, mpc_crypto_message_info_t* info);

// Run a single step in the process on one of the peers	
MPCCRYPTO_API int MPCCrypto_step(MPCCryptoContext* context, MPCCryptoMessage* in, MPCCryptoMessage** out, unsigned* flags);

// Get key share from the context (in case of an updated key share)
MPCCRYPTO_API int MPCCrypto_getShare(MPCCryptoContext* context, MPCCryptoShare** share);

// Refresh
MPCCRYPTO_API int MPCCrypto_initRefreshKey(int peer, MPCCryptoShare* share, MPCCryptoContext** context);

// EdDSA specific functions
MPCCRYPTO_API int MPCCrypto_initGenerateEddsaKey(int peer, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_initEddsaSign(int peer, MPCCryptoShare* share, const uint8_t* in, int in_size, int refresh, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_finalEddsaSign(MPCCryptoContext* context, uint8_t* signature); // |signature|=64
MPCCRYPTO_API int MPCCrypto_verifyEddsa(const uint8_t* pub_key, const uint8_t* in, int in_size, const uint8_t* signature); // |pub_key|=32, |signature|=64
MPCCRYPTO_API int MPCCrypto_getEddsaPublic(MPCCryptoShare* share, uint8_t* pub_key); // |pub_key|=32

// ECDSA specific functions
MPCCRYPTO_API int MPCCrypto_initGenerateEcdsaKey(int peer, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_initEcdsaSign(int peer, MPCCryptoShare* share, const uint8_t* in, int in_size, int refresh, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_finalEcdsaSign(MPCCryptoContext* context, uint8_t* signature, int* out_size); // signature is der-encoded
MPCCRYPTO_API int MPCCrypto_verifyEcdsa(EC_KEY* pub_key, const uint8_t* in, int in_size, const uint8_t* signature, int signature_size); 
MPCCRYPTO_API int MPCCrypto_getEcdsaPublic(MPCCryptoShare* share, EC_KEY** pub_key);

// Generic secret (seed) functions
MPCCRYPTO_API int MPCCrypto_initGenerateGenericSecret(int peer, int bits, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_initImportGenericSecret(int peer, const uint8_t* key, int size, MPCCryptoContext** context);

// Backup functions for ECDSA
MPCCRYPTO_API int MPCCrypto_initBackupEcdsaKey(int peer, MPCCryptoShare* share, RSA* pub_backup_key, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_finalBackupEcdsaKey(MPCCryptoContext* context, uint8_t* out, int* out_size);
MPCCRYPTO_API int MPCCrypto_verifyEcdsaBackupKey(RSA* pub_backup_key, EC_KEY* pub_key, const uint8_t* backup, int backup_size); 
MPCCRYPTO_API int MPCCrypto_restoreEcdsaKey(RSA* prv_backup_key, const uint8_t* backup, int backup_size, EC_KEY** out); 

// Backup functions for EdDSA
MPCCRYPTO_API int MPCCrypto_initBackupEddsaKey(int peer, MPCCryptoShare* share, RSA* pub_backup_key, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_finalBackupEddsaKey(MPCCryptoContext* context, uint8_t* out, int* out_size);
MPCCRYPTO_API int MPCCrypto_verifyEddsaBackupKey(RSA* pub_backup_key, const uint8_t* pub_key, const uint8_t* backup, int backup_size); 
MPCCRYPTO_API int MPCCrypto_restoreEddsaKey(RSA* prv_backup_key, const uint8_t* backup, int backup_size, uint8_t* out);  // |out|=32

// BIP32 functions
MPCCRYPTO_API int MPCCrypto_initDeriveBIP32(int peer, MPCCryptoShare* share, int hardened, unsigned index, MPCCryptoContext** context);
MPCCRYPTO_API int MPCCrypto_finalDeriveBIP32(MPCCryptoContext* context, MPCCryptoShare** new_share);
MPCCRYPTO_API int MPCCrypto_getBIPInfo(MPCCryptoShare* share, bip32_info_t* bip32_info);


#ifdef __cplusplus
}
#endif //__cplusplus
