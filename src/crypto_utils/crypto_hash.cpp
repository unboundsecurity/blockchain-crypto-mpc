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
#include "crypto.h"

namespace crypto
{

static const uint8_t MD2_oid[]     = { 0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x02,0x05,0x00,0x04,0x10 };
static const uint8_t MD4_oid[]     = { 0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x04,0x05,0x00,0x04,0x10 };
static const uint8_t MD5_oid[]     = { 0x30,0x20,0x30,0x0c,0x06,0x08,0x2a,0x86,0x48,0x86,0xf7,0x0d,0x02,0x05,0x05,0x00,0x04,0x10 };
static const uint8_t SHA1_oid[]    = { 0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14 };
static const uint8_t SHA256_oid[]  = { 0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20};
static const uint8_t SHA384_oid[]  = { 0x30,0x41,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x02,0x05,0x00,0x04,0x30};
static const uint8_t SHA512_oid[]  = { 0x30,0x51,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x03,0x05,0x00,0x04,0x40};

static const uint8_t SHA1_init[]   = { 0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54, 0x76, 0xc3, 0xd2, 0xe1, 0xf0};
static const uint8_t SHA256_init[] = { 0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85, 0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a, 0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c, 0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19};
static const uint8_t SHA384_init[] = { 0xcb, 0xbb, 0x9d, 0x5d, 0xc1, 0x05, 0x9e, 0xd8, 0x62, 0x9a, 0x29, 0x2a, 0x36, 0x7c, 0xd5, 0x07, 0x91, 0x59, 0x01, 0x5a, 0x30, 0x70, 0xdd, 0x17, 0x15, 0x2f, 0xec, 0xd8, 0xf7, 0x0e, 0x59, 0x39, 0x67, 0x33, 0x26, 0x67, 0xff, 0xc0, 0x0b, 0x31, 0x8e, 0xb4, 0x4a, 0x87, 0x68, 0x58, 0x15, 0x11, 0xdb, 0x0c, 0x2e, 0x0d, 0x64, 0xf9, 0x8f, 0xa7, 0x47, 0xb5, 0x48, 0x1d, 0xbe, 0xfa, 0x4f, 0xa4};
static const uint8_t SHA512_init[] = { 0x6a, 0x09, 0xe6, 0x67, 0xf3, 0xbc, 0xc9, 0x08, 0xbb, 0x67, 0xae, 0x85, 0x84, 0xca, 0xa7, 0x3b, 0x3c, 0x6e, 0xf3, 0x72, 0xfe, 0x94, 0xf8, 0x2b, 0xa5, 0x4f, 0xf5, 0x3a, 0x5f, 0x1d, 0x36, 0xf1, 0x51, 0x0e, 0x52, 0x7f, 0xad, 0xe6, 0x82, 0xd1, 0x9b, 0x05, 0x68, 0x8c, 0x2b, 0x3e, 0x6c, 0x1f, 0x1f, 0x83, 0xd9, 0xab, 0xfb, 0x41, 0xbd, 0x6b, 0x5b, 0xe0, 0xcd, 0x19, 0x13, 0x7e, 0x21, 0x79};

static const hash_alg_t alg_nohash    = { hash_e::none,      0,   0,   0, mem_t(),                               mem_t(),                                 nullptr         };
static const hash_alg_t alg_md2       = { hash_e::md2,       16,  16,  0, mem_t(MD2_oid,    sizeof(MD2_oid)),    mem_t(),                                 nullptr         };
static const hash_alg_t alg_md4       = { hash_e::md4,       16,  64,  0, mem_t(MD4_oid,    sizeof(MD4_oid)),    mem_t(),                                 EVP_md4()       };
static const hash_alg_t alg_md5       = { hash_e::md5,       16,  64,  0, mem_t(MD5_oid,    sizeof(MD5_oid)),    mem_t(),                                 EVP_md5()       };
static const hash_alg_t alg_sha1      = { hash_e::sha1,      20,  64, 20, mem_t(SHA1_oid,   sizeof(SHA1_oid)),   mem_t(SHA1_init,   sizeof(SHA1_init)),   EVP_sha1()      };
static const hash_alg_t alg_sha256    = { hash_e::sha256,    32,  64, 32, mem_t(SHA256_oid, sizeof(SHA256_oid)), mem_t(SHA256_init, sizeof(SHA256_init)), EVP_sha256()    };
static const hash_alg_t alg_sha384    = { hash_e::sha384,    48, 128, 64, mem_t(SHA384_oid, sizeof(SHA384_oid)), mem_t(SHA384_init, sizeof(SHA384_init)), EVP_sha384()    };
static const hash_alg_t alg_sha512    = { hash_e::sha512,    64, 128, 64, mem_t(SHA512_oid, sizeof(SHA512_oid)), mem_t(SHA512_init, sizeof(SHA512_init)), EVP_sha512()    };
static const hash_alg_t alg_ripemd160 = { hash_e::ripemd160, 20, 64, 20,  mem_t(),                               mem_t(),                                 EVP_ripemd160() };

const hash_alg_t& hash_alg_t::get(hash_e type) // static
{
  switch (type)
  {
    case hash_e::md2       : return alg_md2;
    case hash_e::md4       : return alg_md4;
    case hash_e::md5       : return alg_md5;
    case hash_e::sha1      : return alg_sha1;
    case hash_e::sha256    : return alg_sha256;
    case hash_e::sha384    : return alg_sha384;
    case hash_e::sha512    : return alg_sha512;
    case hash_e::ripemd160: return alg_ripemd160;
  }
  return alg_nohash;
}

// ----------------------------------------- hash_t ----------------------------------------

hash_t& hash_t::init()                    
{ 
#ifndef OPENSSL_MD_PTR
  EVP_MD_CTX* ctx_ptr = &ctx;
#endif

  ::EVP_DigestInit(ctx_ptr, alg.md); 
  return *this;  
}

hash_t& hash_t::update(const_byte_ptr ptr, int size)      
{ 
#ifndef OPENSSL_MD_PTR
  EVP_MD_CTX* ctx_ptr = &ctx;
#endif

  ::EVP_DigestUpdate(ctx_ptr, ptr, size); 
  return *this; 
}

void hash_t::final(byte_ptr out)          
{ 
#ifndef OPENSSL_MD_PTR
  EVP_MD_CTX* ctx_ptr = &ctx;
#endif

  ::EVP_DigestFinal(ctx_ptr, out, NULL);  
}  

buf_t hash_t::final()
{
  buf_t out(alg.size);
  final(out.data());
  return out;
}


buf_t hmac_t::final()
{
  buf_t out(alg.size);
  final(out.data());
  return out;
}
  
 hmac_t& hmac_t::init(mem_t key)
{
#ifndef OPENSSL_HMAC_PTR
  HMAC_CTX* ctx_ptr = &ctx;
#endif
  HMAC_Init_ex(ctx_ptr, key.data, key.size, alg.md, NULL);
  return *this;
}

hmac_t& hmac_t::update(const byte_ptr ptr, int size)
{
#ifndef OPENSSL_HMAC_PTR
  HMAC_CTX* ctx_ptr = &ctx;
#endif

  HMAC_Update(ctx_ptr, ptr, size);
  return *this;
}


void hmac_t::final(byte_ptr out)
{
#ifndef OPENSSL_HMAC_PTR
  HMAC_CTX* ctx_ptr = &ctx;
#endif

  HMAC_Final(ctx_ptr, out, NULL);

#ifdef OPENSSL_HMAC_PTR
  HMAC_CTX_free(ctx_ptr);
  ctx_ptr = HMAC_CTX_new();
#else
  HMAC_CTX_cleanup(ctx_ptr);
  HMAC_CTX_init(ctx_ptr);
#endif

}

// ------------------------- sha256 ------------------------

uint64_t sha256_truncated_uint64(mem_t mem)
{
  buf256_t hash = sha256_t::hash(mem);
  return hash.lo.be_half0();
}

//---------------------------------- hash_state_t ------------------------------

hash_state_t::~hash_state_t()
{
  memset(buffer, 0, sizeof(buffer));
  memset(h64, 0, sizeof(h64));
}

buf_t hash_state_t::get_state() const
{
  buf_t out(alg.state_size);
  get_state(out.data());
  return out;
}

buf_t hash_state_t::final()
{
  buf_t out(alg.size);
  final(out.data());
  return out;
}

void hash_state_t::init()
{
  buf_size = 0;
  full_size = 0;
  switch (alg.type)
  {
    case hash_e::sha512 : sha512_init(); break;
    default : assert(false);
  }
}

void hash_state_t::get_state(byte_ptr state) const
{
  switch (alg.type)
  {
    case hash_e::sha384 : 
    case hash_e::sha512 : sha512_get_state(state); break;
    default : assert(false);
  }
}

void hash_state_t::set_state(const_byte_ptr state, int full_size)
{
  this->full_size = full_size;
  buf_size = 0;

  switch (alg.type)
  {
    case hash_e::sha384 : 
    case hash_e::sha512 : sha512_set_state(state); break;
    default : assert(false);
  }
}


void hash_state_t::transform()
{
  switch (alg.type)
  {
    case hash_e::sha384 : 
    case hash_e::sha512 : sha512_transform(); break;
    default : assert(false);
  }
}

void hash_state_t::update(mem_t in)
{
  for (int i = 0; i < in.size; i++) 
  {
		buffer[buf_size++] = in.data[i];
		if (buf_size == alg.block_size) 
    {
			transform();
      full_size += alg.block_size;
			buf_size = 0;
		}
	}
}

void hash_state_t::final(byte_ptr out)
{
  uint64_t bits = uint64_t(full_size+buf_size)*8;
  int last_block_size = alg.block_size-8;
  buffer[buf_size++] = 0x80;
  while (buf_size < last_block_size) buffer[buf_size++] = 0x00;

  if (buf_size > last_block_size) 
  {
    while (buf_size < alg.block_size) buffer[buf_size++] = 0x00;
    transform();
    memset(buffer, 0, last_block_size);
	}

  ub::be_set_8(buffer+last_block_size, bits);
  transform();

  if (alg.size==alg.state_size)
  {
    get_state(out);
  }
  else
  {
    byte_t buf[128];
    get_state(buf);
    memmove(out, buf, alg.size);
    ub::secure_bzero(buf);
  }
}


// -------------------------- SHA512 -----------------------------------

static const uint64_t sha512_k[80] = { //ULL = uint64
  0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
  0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
  0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65, 0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
  0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
  0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
  0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
  0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
  0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec, 0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
  0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
  0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817};

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << ((sizeof(a)*8)-(b))))

#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0(x)	(ROTRIGHT((x),28) ^ ROTRIGHT((x),34) ^ ROTRIGHT((x),39))
#define Sigma1(x)	(ROTRIGHT((x),14) ^ ROTRIGHT((x),18) ^ ROTRIGHT((x),41))
#define sigma0(x)	(ROTRIGHT((x),1)  ^ ROTRIGHT((x),8)  ^ ((x)>>7))
#define sigma1(x)	(ROTRIGHT((x),19) ^ ROTRIGHT((x),61) ^ ((x)>>6))

void hash_state_t::sha512_init()
{
  h64[0] = 0x6a09e667f3bcc908;  h64[1] = 0xbb67ae8584caa73b;  h64[2] = 0x3c6ef372fe94f82b;  h64[3] = 0xa54ff53a5f1d36f1;
  h64[4] = 0x510e527fade682d1;  h64[5] = 0x9b05688c2b3e6c1f;  h64[6] = 0x1f83d9abfb41bd6b;  h64[7] = 0x5be0cd19137e2179;
}

void hash_state_t::sha512_transform()
{
  uint64_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[80];

	for (i = 0, j = 0; i < 16; ++i, j += 8) m[i] = ub::be_get_8(buffer+j);
	for (; i < 80; ++i) m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];

	a = h64[0];	b = h64[1];	c = h64[2];	d = h64[3];	e = h64[4];	f = h64[5];	g = h64[6];	h = h64[7];

	for (i = 0; i < 80; ++i) 
  {
		t1 = h + Sigma1(e) + CH(e, f, g) + sha512_k[i] + m[i];
		t2 = Sigma0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	h64[0] += a;	h64[1] += b;	h64[2] += c;	h64[3] += d;	h64[4] += e;	h64[5] += f;	h64[6] += g;	h64[7] += h;
}

void hash_state_t::sha512_get_state(byte_ptr state) const
{
  for (int i=0; i<8; i++) ub::be_set_8(state + i*8, h64[i]);
}

void hash_state_t::sha512_set_state(const_byte_ptr state)
{
  for (int i=0; i<8; i++) h64[i] = ub::be_get_8(state + i*8);
}



} // namespace crypto
