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
#include "mpc_crypto.h"

void help()
{
  printf("USAGE: mpc_crypto_bench [ecdsa-gen|ecdsa-sign|eddsa-gen|eddsa-sign|bip-initial|bip-hardened|bip-normal] <iterations>\n");
  exit(-1);
}

void halt(int rv)
{
  printf("\nError %08x occured\n", rv);
  exit(rv);
}

class bench_t
{
public:
  bench_t();
  virtual ~bench_t();
  virtual void init() {}
  virtual void run() = 0;

protected:

  MPCCryptoShare* client_share;
  MPCCryptoShare* server_share;
  MPCCryptoContext* client_ctx;
  MPCCryptoContext* server_ctx;

  void run_protocol();
  void free_shares();
  void free_ctx();
};

bench_t::bench_t() : client_share(nullptr), server_share(nullptr), client_ctx(nullptr), server_ctx(nullptr)
{
}

bench_t::~bench_t()
{
  free_ctx();
  free_shares();
}

void bench_t::free_shares()
{
  MPCCrypto_freeShare(client_share); client_share = nullptr;
  MPCCrypto_freeShare(server_share); server_share = nullptr;
}

void bench_t::free_ctx()
{
  MPCCrypto_freeContext(client_ctx); client_ctx = nullptr;
  MPCCrypto_freeContext(server_ctx); server_ctx = nullptr;  
}

void bench_t::run_protocol()
{
  bool client_finished = false;
  bool server_finished = false;

  MPCCryptoMessage* in = nullptr;
  MPCCryptoMessage* out = nullptr;

  while (!client_finished || !server_finished)
  {  
    int rv = 0;

    if (!client_finished)
    {
      unsigned flags = 0;
      if (rv = MPCCrypto_step(client_ctx, in, &out, &flags)) return halt(rv);
      if (in) MPCCrypto_freeMessage(in);
      in = out;
      client_finished =  (flags & mpc_protocol_finished) != 0;
    }

    if (!out) break;

    if (!server_finished)
    {
      unsigned flags = 0;
      if (rv = MPCCrypto_step(server_ctx, in, &out, &flags)) return halt(rv);
      if (in) MPCCrypto_freeMessage(in);
      in = out;
      server_finished =  (flags & mpc_protocol_finished) != 0;
    }
  }
}

class ecdsa_gen_t : public bench_t 
{ 
public:
  void run()
  {
    int rv = 0;
    if (rv = MPCCrypto_initGenerateEcdsaKey(1, &client_ctx)) halt(rv);
    if (rv = MPCCrypto_initGenerateEcdsaKey(2, &server_ctx)) halt(rv);
    run_protocol();
    free_ctx();
  }
};

class ecdsa_sign_t : public bench_t 
{ 
public:
  void init()
  {
    int rv = 0;
    if (rv = MPCCrypto_initGenerateEcdsaKey(1, &client_ctx)) halt(rv);
    if (rv = MPCCrypto_initGenerateEcdsaKey(2, &server_ctx)) halt(rv);
    run_protocol();
    if (rv = MPCCrypto_getShare(client_ctx, &client_share)) halt(rv);
    if (rv = MPCCrypto_getShare(server_ctx, &server_share)) halt(rv);
  }

  void run()
  {
    char test[] = "123456";  

    int rv = 0;
    if (rv = MPCCrypto_initEcdsaSign(1, client_share, (const uint8_t*)test, sizeof(test), 0, &client_ctx)) halt(rv);
    if (rv = MPCCrypto_initEcdsaSign(2, server_share, (const uint8_t*)test, sizeof(test), 0, &server_ctx)) halt(rv);
    
    run_protocol();

    int sig_size = 0;
    if (rv = MPCCrypto_getResultEcdsaSign(client_ctx, nullptr, &sig_size)) halt(rv);
    std::vector<uint8_t> sig(sig_size);
    if (rv = MPCCrypto_getResultEcdsaSign(client_ctx, sig.data(), &sig_size)) halt(rv);
  }

};

class eddsa_sign_t : public bench_t 
{ 
public:
  void init()
  {
    int rv = 0;
    if (rv = MPCCrypto_initGenerateEddsaKey(1, &client_ctx)) halt(rv);
    if (rv = MPCCrypto_initGenerateEddsaKey(2, &server_ctx)) halt(rv);
    run_protocol();
    if (rv = MPCCrypto_getShare(client_ctx, &client_share)) halt(rv);
    if (rv = MPCCrypto_getShare(server_ctx, &server_share)) halt(rv);
  }

  void run()
  {
    char test[] = "123456";  

    int rv = 0;
    if (rv = MPCCrypto_initEddsaSign(1, client_share, (const uint8_t*)test, sizeof(test), 0, &client_ctx)) halt(rv);
    if (rv = MPCCrypto_initEddsaSign(2, server_share, (const uint8_t*)test, sizeof(test), 0, &server_ctx)) halt(rv);
    
    run_protocol();

    uint8_t sig[64];
    if (rv = MPCCrypto_getResultEddsaSign(client_ctx, sig)) halt(rv);
  }

};

class eddsa_gen_t : public bench_t 
{ 
public:
  void run()
  {
    int rv = 0;
    if (rv = MPCCrypto_initGenerateEddsaKey(1, &client_ctx)) halt(rv);
    if (rv = MPCCrypto_initGenerateEddsaKey(2, &server_ctx)) halt(rv);
    run_protocol();
    free_ctx();
  }
};

class bip_t : public bench_t 
{ 
public:
  bip_t(int _mode) : mode(_mode) {}

  void init()
  {
    uint8_t seed[16] = {1,2,3,4,5};
    int rv = 0;
    if (rv = MPCCrypto_initImportGenericSecret(1, seed, sizeof(seed), &client_ctx)) halt(rv);
    if (rv = MPCCrypto_initImportGenericSecret(2, seed, sizeof(seed), &server_ctx)) halt(rv);
    run_protocol();
    if (rv = MPCCrypto_getShare(client_ctx, &client_share)) halt(rv);
    if (rv = MPCCrypto_getShare(server_ctx, &server_share)) halt(rv);
    free_ctx();

    if (mode<0) mode = 0;
    else
    {
      if (rv = MPCCrypto_initDeriveBIP32(1, client_share, 0, 0, &client_ctx)) halt(rv);
      if (rv = MPCCrypto_initDeriveBIP32(2, server_share, 0, 0, &server_ctx)) halt(rv);
      run_protocol();
      free_shares();
      if (rv = MPCCrypto_getResultDeriveBIP32(client_ctx, &client_share)) halt(rv);
      if (rv = MPCCrypto_getResultDeriveBIP32(server_ctx, &server_share)) halt(rv);
      free_ctx();    
    }
  }

  void run()
  {
    int rv = 0;
    if (rv = MPCCrypto_initDeriveBIP32(1, client_share, mode, 0, &client_ctx)) halt(rv);
    if (rv = MPCCrypto_initDeriveBIP32(2, server_share, mode, 0, &server_ctx)) halt(rv);
    run_protocol();
    free_ctx();
  }

private:
  int mode;
};

int main(int argc, char* argv[])
{
  if (argc<3) help();
  int count = atoi(argv[2]);
  if (count<=0) count = 1;

  const char* name = argv[1];
  bench_t* bench = nullptr;

  if (false);
  else if (0==strcmp(name, "ecdsa-gen")) bench = new ecdsa_gen_t();
  else if (0==strcmp(name, "ecdsa-sign")) bench = new ecdsa_sign_t();
  else if (0==strcmp(name, "eddsa-gen")) bench = new eddsa_gen_t();
  else if (0==strcmp(name, "eddsa-sign")) bench = new eddsa_sign_t();
  else if (0==strcmp(name, "bip-initial")) bench = new bip_t(-1);
  else if (0==strcmp(name, "bip-hardened")) bench = new bip_t(1);
  else if (0==strcmp(name, "bip-normal")) bench = new bip_t(0);
  else help();

  printf("Initialization... "); fflush(stdout);
  bench->init();
  printf("\n");

  printf("Running %s for %d iterations\n", name, count);
  std::chrono::high_resolution_clock::time_point begin = std::chrono::high_resolution_clock::now();
  for (int i=0; i<count; i++)
  {
    printf("."); fflush(stdout);
    bench->run();
  }
  std::chrono::high_resolution_clock::time_point end = std::chrono::high_resolution_clock::now();
  double duration = (double)std::chrono::duration_cast<std::chrono::milliseconds>(end - begin).count();
  printf("\n%f seconds per operation\n", duration / (count * 1000));

  delete bench;
	return 0;
}

