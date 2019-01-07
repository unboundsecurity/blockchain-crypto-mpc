/*
 *     NOTICE
 *
 *     The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
 *     If you choose to receive it under the GPL v.3 license, the following applies:
 *     Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
 *     
 *     Copyright (C) 2018, Unbound Tech Ltd. 
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
#include "mpc_crypto.h"
#include "mpc_ot.h"
#include "mpc_ecc_core.h"

extern "C" MPCCRYPTO_API int MPCCrypto_test();

static int share_to_buf(MPCCryptoShare* share, std::vector<uint8_t>& buf)
{
  int rv = 0;
  int size = 0;
  if (rv = MPCCrypto_shareToBuf(share, nullptr, &size)) return rv;
  buf.resize(size);
  if (rv = MPCCrypto_shareToBuf(share, buf.data(), &size)) return rv;
  return 0;
}

static int share_from_buf(const std::vector<uint8_t>& mem, MPCCryptoShare*& share)
{
  return MPCCrypto_shareFromBuf(mem.data(), (int)mem.size(), &share);
}

static int message_to_buf(MPCCryptoMessage* message, std::vector<uint8_t>& buf)
{
  int rv = 0;
  int size = 0;
  if (rv = MPCCrypto_messageToBuf(message, nullptr, &size)) return rv;
  buf.resize(size);
  if (rv = MPCCrypto_messageToBuf(message, buf.data(), &size)) return rv;
  return 0;
}

static int message_from_buf(const std::vector<uint8_t>& mem, MPCCryptoMessage*& message)
{
  return MPCCrypto_messageFromBuf(mem.data(), (int)mem.size(), &message);
}

static int context_to_buf(MPCCryptoContext* context, std::vector<uint8_t>& buf)
{
  int rv = 0;
  int size = 0;
  if (rv = MPCCrypto_contextToBuf(context, nullptr, &size)) return rv;
  buf.resize(size);
  if (rv = MPCCrypto_contextToBuf(context, buf.data(), &size)) return rv;
  return 0;
}

static int context_from_buf(const std::vector<uint8_t>& mem, MPCCryptoContext*& context)
{
  return MPCCrypto_contextFromBuf(mem.data(), (int)mem.size(), &context);
}

struct test_key_t
{
  MPCCryptoShare* client;
  MPCCryptoShare* server;

  test_key_t() : client(nullptr), server(nullptr) {}
  ~test_key_t() { MPCCrypto_freeShare(client); MPCCrypto_freeShare(server); }
};

struct test_context_t
{
  MPCCryptoContext* client;
  MPCCryptoContext* server;
  test_context_t() : client(nullptr), server(nullptr) {}
  ~test_context_t() { MPCCrypto_freeContext(client); MPCCrypto_freeContext(server); }
};


static int client_step(test_key_t& test_key, test_context_t& test_context, std::vector<uint8_t>& message_buf, bool& finished)
{
  int rv = 0;

  MPCCryptoMessage* in = nullptr;
  MPCCryptoMessage* out = nullptr;

  if (!message_buf.empty())
  {
    if (rv = message_from_buf(message_buf, in)) return rv;
  }

  unsigned flags = 0;
  if (rv = MPCCrypto_step(test_context.client, in, &out, &flags)) return rv;
  if (in) MPCCrypto_freeMessage(in);
  
  std::vector<uint8_t> context_buf;
  if (rv = context_to_buf(test_context.client, context_buf)) return rv;
  MPCCrypto_freeContext(test_context.client); test_context.client = nullptr;
  if (rv = context_from_buf(context_buf, test_context.client)) return rv;

  finished =  (flags & mpc_protocol_finished) != 0;

  if (flags & mpc_share_changed)
  {
    MPCCrypto_freeShare(test_key.client); test_key.client = nullptr;
    if (rv = MPCCrypto_getShare(test_context.client, &test_key.client)) return rv;
    std::vector<uint8_t> share_buf;
    if (rv = share_to_buf(test_key.client, share_buf)) return rv;
    MPCCrypto_freeShare(test_key.client); test_key.client = nullptr;
    if (rv = share_from_buf(share_buf, test_key.client)) return rv;
  }
  
  if (out)
  {
    if (rv = message_to_buf(out, message_buf)) return rv;
    MPCCrypto_freeMessage(out);
  }
  else message_buf.clear();

  return rv; 
}

uint64_t last_server_context_uid = 0;

static int server_step(test_key_t& test_key, test_context_t& test_context, std::vector<uint8_t>& message_buf, bool& finished)
{
  int rv = 0;

  MPCCryptoMessage* in = nullptr;
  MPCCryptoMessage* out = nullptr;

  if (rv = message_from_buf(message_buf, in)) return rv;

  mpc_crypto_message_info_t message_info;
  if (rv = MPCCrypto_messageInfo(in, &message_info)) return rv;

  unsigned flags = 0;
  if (rv = MPCCrypto_step(test_context.server, in, &out, &flags)) return rv;
  if (in) MPCCrypto_freeMessage(in);

  std::vector<uint8_t> context_buf;
  if (rv = context_to_buf(test_context.server, context_buf)) return rv;
  MPCCrypto_freeContext(test_context.server); test_context.server = nullptr;
  if (rv = context_from_buf(context_buf, test_context.server)) return rv;

  finished =  (flags & mpc_protocol_finished) != 0;

  if (flags & mpc_share_changed)
  {
    MPCCrypto_freeShare(test_key.server); test_key.server = nullptr;
    if (rv = MPCCrypto_getShare(test_context.server, &test_key.server)) return rv;
    std::vector<uint8_t> share_buf;
    if (rv = share_to_buf(test_key.server, share_buf)) return rv;
    MPCCrypto_freeShare(test_key.server); test_key.server = nullptr;
    if (rv = share_from_buf(share_buf, test_key.server)) return rv;
  }

  if (out) 
  {
    if (rv = message_to_buf(out, message_buf)) return rv;
    MPCCrypto_freeMessage(out);
  }
  else message_buf.clear();

  return rv;
}

static int test_client_server(test_key_t& test_key, test_context_t& test_context)
{
  int rv = 0;

  bool client_finished = false;
  bool server_finished = false;

  std::vector<uint8_t> message_buf;

  while (!client_finished || !server_finished)
  {  
    if (!client_finished)
    {
      if (rv = client_step(test_key, test_context, message_buf, client_finished)) return rv;
    }

    if (message_buf.empty()) break;

    if (!server_finished)
    {
      if (rv = server_step(test_key, test_context, message_buf, server_finished)) return rv;
    }
  }

  return 0;
}

static int test_ecdsa_gen(test_key_t& test_key)
{
  int rv = 0;
  printf("test_ecdsa_gen...");

  test_context_t test_context;
  if (rv = MPCCrypto_initGenerateEcdsaKey(1, &test_context.client)) return rv;
  if (rv = MPCCrypto_initGenerateEcdsaKey(2, &test_context.server)) return rv;
  if (rv = test_client_server(test_key, test_context)) return rv;

  printf(" ok\n");
  return rv;
}

static RSA* generate_rsa_key()
{
  BIGNUM* e = BN_new();
  BN_set_word(e, 65537);
  RSA* rsa_key = RSA_new(); 
  RSA_generate_key_ex(rsa_key, 2048, e, NULL);
  return rsa_key;
}

static std::vector<uint8_t> export_rsa_pub_key_info(RSA* rsa_key)
{
  std::vector<uint8_t> out;
  int out_size = i2d_RSA_PUBKEY(rsa_key, nullptr);
  if (out_size>0) 
  {
    out.resize(out_size);
    uint8_t* out_ptr = &out[0];
    i2d_RSA_PUBKEY(rsa_key, &out_ptr);
  }
  return out;
}


static std::vector<uint8_t> export_rsa_pkcs8_prv(RSA* rsa_key)
{
  std::vector<uint8_t> out;

  EVP_PKEY* evp_key = EVP_PKEY_new();
  EVP_PKEY_set1_RSA(evp_key, rsa_key);

  PKCS8_PRIV_KEY_INFO* pkcs8 = EVP_PKEY2PKCS8(evp_key);
  int out_size = i2d_PKCS8_PRIV_KEY_INFO(pkcs8, NULL);

  if (out_size>0)
  {
    out.resize(out_size);
    uint8_t* out_ptr = &out[0];
    i2d_PKCS8_PRIV_KEY_INFO(pkcs8, &out_ptr);
  }

  PKCS8_PRIV_KEY_INFO_free(pkcs8);
  EVP_PKEY_free(evp_key);

  return out;
}


static int test_ecdsa_backup(test_key_t& test_key)
{
  int rv = 0;
  printf("test_ecdsa_backup...");

  RSA* backup_rsa_key = generate_rsa_key();
  std::vector<uint8_t> backup_rsa_key_pub = export_rsa_pub_key_info(backup_rsa_key);
  std::vector<uint8_t> backup_rsa_key_prv = export_rsa_pkcs8_prv(backup_rsa_key);
  RSA_free(backup_rsa_key);

  test_context_t test_context;
  if (rv = MPCCrypto_initBackupEcdsaKey(1, test_key.client, backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), &test_context.client)) return rv;
  if (rv = MPCCrypto_initBackupEcdsaKey(2, test_key.server, backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), &test_context.server)) return rv;
  if (rv = test_client_server(test_key, test_context)) return rv;

  int backup_size = 0;
  if (rv = MPCCrypto_getResultBackupEcdsaKey(test_context.client, nullptr, &backup_size)) return rv;
  std::vector<uint8_t> backup(backup_size);
  if (rv = MPCCrypto_getResultBackupEcdsaKey(test_context.client, backup.data(), &backup_size)) return rv;

  int pub_key_size = 0;
  if (rv = MPCCrypto_getEcdsaPublic(test_key.client, nullptr, &pub_key_size)) return rv;
  std::vector<uint8_t> pub_ec_key(pub_key_size);
  if (rv = MPCCrypto_getEcdsaPublic(test_key.client, pub_ec_key.data(), &pub_key_size)) return rv;

  if (rv = MPCCrypto_verifyEcdsaBackupKey(backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), pub_ec_key.data(), (int)pub_ec_key.size(), backup.data(), backup_size)) return rv;

  int prv_key_size = 0;
  if (rv = MPCCrypto_restoreEcdsaKey(backup_rsa_key_prv.data(), (int)backup_rsa_key_prv.size(), pub_ec_key.data(), (int)pub_ec_key.size(), backup.data(), backup_size, nullptr, &prv_key_size)) return rv;
  std::vector<uint8_t> prv_ec_key(prv_key_size);
  if (rv = MPCCrypto_restoreEcdsaKey(backup_rsa_key_prv.data(), (int)backup_rsa_key_prv.size(), pub_ec_key.data(), (int)pub_ec_key.size(), backup.data(), backup_size, prv_ec_key.data(), &prv_key_size)) return rv;

  printf(" ok\n");
  return rv;
}

static int test_ecdsa_sign(test_key_t& test_key)
{
  int rv = 0;
  printf("test_ecdsa_sign...");

  char test[] = "123456";  

  test_context_t test_context;
  if (rv = MPCCrypto_initEcdsaSign(1, test_key.client, (const uint8_t*)test, sizeof(test), 1, &test_context.client)) return rv;
  if (rv = MPCCrypto_initEcdsaSign(2, test_key.server, (const uint8_t*)test, sizeof(test), 1, &test_context.server)) return rv;

  if (rv = test_client_server(test_key, test_context)) return rv;

  int sig_size = 0;
  if (rv = MPCCrypto_getResultEcdsaSign(test_context.client, nullptr, &sig_size)) return rv;
  std::vector<uint8_t> sig(sig_size);
  if (rv = MPCCrypto_getResultEcdsaSign(test_context.client, sig.data(), &sig_size)) return rv;

  int pub_key_size = 0;
  if (rv = MPCCrypto_getEcdsaPublic(test_key.client, nullptr, &pub_key_size)) return rv;
  std::vector<uint8_t> pub_ec_key(pub_key_size);
  if (rv = MPCCrypto_getEcdsaPublic(test_key.client, pub_ec_key.data(), &pub_key_size)) return rv;

  if (rv = MPCCrypto_verifyEcdsa(pub_ec_key.data(), (int)pub_ec_key.size(), (const uint8_t*)test, sizeof(test), sig.data(), sig_size)) return rv;

  printf(" ok\n");
  return rv;
}

static int test_eddsa_gen(test_key_t& test_key)
{
  int rv = 0;
  printf("test_eddsa_gen...");

  test_context_t test_context;
  if (rv = MPCCrypto_initGenerateEddsaKey(1, &test_context.client)) return rv;
  if (rv = MPCCrypto_initGenerateEddsaKey(2, &test_context.server)) return rv;
  
  if (rv = test_client_server(test_key, test_context)) return rv;
  printf(" ok\n");
  return rv;
}

static int test_eddsa_backup(test_key_t& test_key)
{
  int rv = 0;
  printf("test_eddsa_backup...");
  
  RSA* backup_rsa_key = generate_rsa_key();
  std::vector<uint8_t> backup_rsa_key_pub = export_rsa_pub_key_info(backup_rsa_key);
  std::vector<uint8_t> backup_rsa_key_prv = export_rsa_pkcs8_prv(backup_rsa_key);
  RSA_free(backup_rsa_key);

  test_context_t test_context;
  if (rv = MPCCrypto_initBackupEddsaKey(1, test_key.client, backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), &test_context.client)) return rv;
  if (rv = MPCCrypto_initBackupEddsaKey(2, test_key.server, backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), &test_context.server)) return rv;
  if (rv = test_client_server(test_key, test_context)) return rv;

  int backup_size = 0;
  if (rv = MPCCrypto_getResultBackupEddsaKey(test_context.client, nullptr, &backup_size)) return rv;
  std::vector<uint8_t> backup(backup_size);
  if (rv = MPCCrypto_getResultBackupEddsaKey(test_context.client, backup.data(), &backup_size)) return rv;

  uint8_t pub_eddsa_key[32];
  if (rv = MPCCrypto_getEddsaPublic(test_key.client, pub_eddsa_key)) return rv;

  if (rv = MPCCrypto_verifyEddsaBackupKey(backup_rsa_key_pub.data(), (int)backup_rsa_key_pub.size(), pub_eddsa_key, backup.data(), backup_size)) return rv;
  uint8_t prv_eeddsa_key[32];
  if (rv = MPCCrypto_restoreEddsaKey(backup_rsa_key_prv.data(), (int)backup_rsa_key_prv.size(), pub_eddsa_key, backup.data(), backup_size, prv_eeddsa_key)) return rv;

  printf(" ok\n");
  return rv;
}


static int test_eddsa_sign(test_key_t& test_key)
{
  int rv = 0;
  printf("test_eddsa_sign...");
  uint8_t sig[64];

  char test[] = "123456";  

  test_context_t test_context;
  if (rv = MPCCrypto_initEddsaSign(1, test_key.client, (const uint8_t*)test, sizeof(test), 1, &test_context.client)) return rv;
  if (rv = MPCCrypto_initEddsaSign(2, test_key.server, (const uint8_t*)test, sizeof(test), 1, &test_context.server)) return rv;
  
  if (rv = test_client_server(test_key, test_context)) return rv;

  if (rv = MPCCrypto_getResultEddsaSign(test_context.client, sig)) return rv;

  uint8_t pub_key[32];
  if (rv = MPCCrypto_getEddsaPublic(test_key.client, pub_key)) return rv;
  if (rv = MPCCrypto_verifyEddsa(pub_key, (const uint8_t*)test, sizeof(test), sig)) return rv;

  printf(" ok\n");
  return rv;
}


int test_refresh(test_key_t& test_key)
{
  int rv = 0;
  printf("test_refresh...");

  test_context_t test_context;
  if (rv = MPCCrypto_initRefreshKey(1, test_key.client, &test_context.client)) return rv;
  if (rv = MPCCrypto_initRefreshKey(2, test_key.server, &test_context.server)) return rv;

  if (rv = test_client_server(test_key, test_context)) return rv;
  
  printf(" ok\n");
  return rv;
}

static int test_generic_secret_gen(test_key_t& test_key)
{
  int rv = 0;
  printf("test_generic_secret_gen...");

  test_context_t test_context;
  if (rv = MPCCrypto_initGenerateGenericSecret(1, 256, &test_context.client)) return rv;
  if (rv = MPCCrypto_initGenerateGenericSecret(2, 256, &test_context.server)) return rv;
  
  if (rv = test_client_server(test_key, test_context)) return rv;
  printf(" ok\n");
  return rv;
}

static int test_generic_secret_import(test_key_t& test_key)
{
  int rv = 0;
  printf("test_generic_secret_import...");
  std::vector<uint8_t> value(32);
  RAND_bytes(value.data(), 32);

  test_context_t test_context;
  if (rv = MPCCrypto_initImportGenericSecret(1, value.data(), (int)value.size(), &test_context.client)) return rv;
  if (rv = MPCCrypto_initImportGenericSecret(2, value.data(), (int)value.size(), &test_context.server)) return rv;
  
  if (rv = test_client_server(test_key, test_context)) return rv;
  printf(" ok\n");
  return rv;
}

static int test_bip_serialize(test_key_t& key, const std::string& test)
{
  int rv = 0;
  
  int ser_size = 0;
  if (rv = MPCCrypto_serializePubBIP32(key.client, nullptr, &ser_size)) return rv;
  char* s = new char[ser_size+1];
  if (rv = MPCCrypto_serializePubBIP32(key.client, s, &ser_size)) return rv;

  if (s!=test) rv = MPC_E_CRYPTO;
  delete[] s;
  return rv;
}

static int hex2int(char input)
{
  if (input >= '0' && input <= '9') return input - '0';
  if (input >= 'A' && input <= 'F') return input - 'A' + 10;
  if (input >= 'a' && input <= 'f') return input - 'a' + 10;
  return -1;
}

static std::vector<uint8_t> hex2bin(const std::string& src)
{
  int dst_size = (int)src.length()/2;
  std::vector<uint8_t> dst(dst_size);
  for (int i=0; i<dst_size; i++) dst[i] = hex2int(src[i*2])*16 + hex2int(src[i*2+1]);
  return dst;
}

static int test_bip_master(test_key_t& key, const std::string& seed, const std::string& test)
{
  printf("test_bip_master...");

  int rv = 0;
  std::vector<uint8_t> seed_key = hex2bin(seed);

  test_context_t import;
  if (rv = MPCCrypto_initImportGenericSecret(1, seed_key.data(), (int)seed_key.size(), &import.client)) return rv;
  if (rv = MPCCrypto_initImportGenericSecret(2, seed_key.data(), (int)seed_key.size(), &import.server)) return rv; 
  test_key_t test_seed_key;
  if (rv = test_client_server(test_seed_key, import)) return rv;

  test_context_t test_context;
  if (rv = MPCCrypto_initDeriveBIP32(1, test_seed_key.client, 0, 0, &test_context.client)) return rv;
  if (rv = MPCCrypto_initDeriveBIP32(2, test_seed_key.server, 0, 0, &test_context.server)) return rv;
  if (rv = test_client_server(test_seed_key, test_context)) return rv;

  if (rv = MPCCrypto_getResultDeriveBIP32(test_context.client, &key.client)) return rv;
  if (rv = MPCCrypto_getResultDeriveBIP32(test_context.server, &key.server)) return rv;

  //if (rv = test_refresh(bip.key)) return rv;
  if (rv = test_bip_serialize(key, test)) return rv;
  //if (rv = test_ecdsa_sign(key)) return rv;
  printf(" ok\n");
  return rv;
}

static int test_bip_derive(test_key_t& src, bool hardened, unsigned index, test_key_t& dst, const std::string& test)
{
  printf("test_bip_derive...");
  int rv = 0;

  test_context_t test_context;
  if (rv = MPCCrypto_initDeriveBIP32(1, src.client, hardened ? 1 : 0, index, &test_context.client)) return rv;
  if (rv = MPCCrypto_initDeriveBIP32(2, src.server, hardened ? 1 : 0, index, &test_context.server)) return rv;
  if (rv = test_client_server(src, test_context)) return rv;
  if (rv = MPCCrypto_getResultDeriveBIP32(test_context.client, &dst.client)) return rv;
  if (rv = MPCCrypto_getResultDeriveBIP32(test_context.server, &dst.server)) return rv;

  //if (rv = test_refresh(dst.key)) return rv;
  if (rv = test_bip_serialize(dst, test)) return rv;
  //if (rv = test_ecdsa_sign(dst)) return rv;
  printf(" ok\n");
  return rv;
}


static int test_bip()
{
  int rv = 0;

  {
    test_key_t m, m_0H, m_0H_1, m_0H_1_2H, m_0H_1_2H_2, m_0H_1_2H_2_1000000000;
    if (rv = test_bip_master(m, "000102030405060708090a0b0c0d0e0f", "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")) return rv;
    if (rv = test_bip_derive(m, true, 0, m_0H, "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")) return rv;
    if (rv = test_bip_derive(m_0H, false, 1, m_0H_1, "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")) return rv;
    if (rv = test_bip_derive(m_0H_1, true, 2, m_0H_1_2H, "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")) return rv;
    if (rv = test_bip_derive(m_0H_1_2H, false, 2, m_0H_1_2H_2, "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")) return rv;
    if (rv = test_bip_derive(m_0H_1_2H_2, false, 1000000000, m_0H_1_2H_2_1000000000, "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")) return rv;
  }

  {
    test_key_t m, m_0, m_0_2147483647H, m_0_2147483647H_1, m_0_2147483647H_1_2147483646H, m_0_2147483647H_1_2147483646H_2;
    if (rv = test_bip_master(m, "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542", "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB")) return rv;
    if (rv = test_bip_derive(m, false, 0, m_0, "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH")) return rv;
    if (rv = test_bip_derive(m_0, true, 2147483647, m_0_2147483647H, "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a")) return rv;
    if (rv = test_bip_derive(m_0_2147483647H, false, 1, m_0_2147483647H_1, "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon")) return rv;
    if (rv = test_bip_derive(m_0_2147483647H_1, true, 2147483646, m_0_2147483647H_1_2147483646H, "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL")) return rv;
    if (rv = test_bip_derive(m_0_2147483647H_1_2147483646H, false, 2, m_0_2147483647H_1_2147483646H_2, "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt")) return rv;
  }

  {
    test_key_t m, m_0;
    if (rv = test_bip_master(m, "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be", "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13")) return rv;
    if (rv = test_bip_derive(m, true, 0, m_0, "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y")) return rv;
  }


  return rv;
}

namespace mpc {
extern int zk_paillier_range_time;
}

MPCCRYPTO_API int MPCCrypto_test()
{
  int rv = 0;
  /*
  test_key_t eddsa_key;
  if (rv = test_eddsa_gen(eddsa_key)) return rv;
  if (rv = test_eddsa_backup(eddsa_key)) return rv;
  for (int i=0; i<3; i++)
  {
    if (rv = test_eddsa_sign(eddsa_key)) return rv;
    if (rv = test_refresh(eddsa_key)) return rv;
  }

  */
  test_key_t ecdsa_key;
  if (rv = test_ecdsa_gen(ecdsa_key)) return rv;

  uint64_t t = ub::read_timer_ms();
  for (int i=0; i<10; i++)
  {
    if (rv = test_ecdsa_sign(ecdsa_key)) return rv;
  }
  t = ub::read_timer_ms() - t;

  /*
  if (rv = test_ecdsa_backup(ecdsa_key)) return rv;
  for (int i=0; i<3; i++)
  {
    if (rv = test_ecdsa_sign(ecdsa_key)) return rv;
    if (rv = test_refresh(ecdsa_key)) return rv;
  }


  if (rv = test_bip()) return rv;

  test_key_t secret_key1; if (rv = test_generic_secret_import(secret_key1)) return rv;
  test_key_t secret_key2; if (rv = test_generic_secret_gen(secret_key2)) return rv;
  for (int i = 0; i<3; i++)
  {
    if (rv = test_refresh(secret_key2)) return rv;
  }
  */
  printf("\nAll tests successfully finished. 10 Signatures took %d ms\n", t);
  return rv;
}

