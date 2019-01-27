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
#include "mpc_core.h"
#include "mpc_ot.h"

using namespace ub;
using namespace crypto;

namespace mpc {

// --------------------------- ot_prepare_t --------------------------

void ot_base_init_t::clear()
{
  Y.clear();
  for (int i=0; i<128; i++) { y[i]=0; }
}

void ot_base_init_t::rec_step1(ot_receiver_t& rec, message1_t& out)
{
  rec.counter = 0;
  const ecc_generator_point_t& G = crypto::curve_p256.generator();
  Y.resize(128);

  for (int i=0; i<128; i++)
  {
    y[i] = crypto::curve_p256.get_random_value();
    Y[i] = G * y[i];
  }

  out.Y = Y;
}

static buf128_t OT_KDF(const crypto::ecc_point_t& P1, const crypto::ecc_point_t& P2, const crypto::ecc_point_t& P3)
{
  return buf256_t(sha256_t::hash(P1, P2, P3)).lo;
}

// rec -> snd : Y
error_t ot_base_init_t::snd_step2(ot_sender_t& snd, const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  if (in.Y.size()!=128) return rv = ub::error(E_BADARG);
  const ecc_generator_point_t& G = crypto::curve_p256.generator();
  snd.counter = 0;
  out.R.resize(128);

  snd.delta = buf128_t::rand();

  for (int i=0; i<128; i++)
  {
    bn_t r = crypto::curve_p256.get_random_value();
    out.R[i] = G * r;
    if (snd.delta.get_bit(i)) out.R[i] += in.Y[i]; // EC addition

    buf128_t kb =  OT_KDF(in.Y[i], out.R[i], in.Y[i] * r);
    snd.keys_tb[i] = kb;
    snd.ecb_keys_tb[i].encrypt_init(mem_t(kb));
  }

  clear();
  return 0;
}

// snd -> rec : R
error_t ot_base_init_t::rec_step3(ot_receiver_t& rec, const message2_t& in)
{
  error_t rv = 0;
  if (in.R.size()!=128) return rv = ub::error(E_BADARG);
  
  for (int i=0; i<128; i++)
  {
    buf128_t k0 = OT_KDF(Y[i], in.R[i], in.R[i] * y[i]);
    buf128_t k1 = OT_KDF(Y[i], in.R[i], (in.R[i] - Y[i]) * y[i]);

    rec.keys_t0[i] = k0;
    rec.keys_t1[i] = k1;

    rec.ecb_keys_t0[i].encrypt_init(mem_t(k0));
    rec.ecb_keys_t1[i].encrypt_init(mem_t(k1));
  }

  clear();
  return rv;
}

// --------------------------- ot_extend_t --------------------------
#ifdef INTEL_X64
static void sse_trans(uint8_t const *inp, uint8_t *out, int nrows, int ncols)
{
  
#define INP_BYTE(x,y) inp[(x)*ncols/8 + (y)/8]
#define OUT_BYTE(x,y) out[(y)*nrows/8 + (x)/8]
  union { __m128i x; uint8_t b[16]; } tmp;
  assert(nrows % 8 == 0 && ncols % 8 == 0);

  // Do the main body in 16x8 blocks:
  for (int rr = 0; rr < nrows; rr += 16) 
  {
    for (int cc = 0; cc < ncols; cc += 8) 
    {
      for (int i = 0; i < 16; ++i)
        tmp.b[i] = INP_BYTE(rr + i, cc);

      for (int i = 8; --i >= 0; tmp.x = _mm_slli_epi64(tmp.x, 1))
        *(uint16_t*)&OUT_BYTE(rr,cc+i)= _mm_movemask_epi8(tmp.x);
    }
  }
}
#endif

static void transpose_128x128(buf128_t dst[128], buf128_t src[128])
{
#ifdef INTEL_X64
  sse_trans(const_byte_ptr(src), byte_ptr(dst), 128, 128);
#else
  uint64_t s[128][2];
  uint64_t d[128][2];

  memset(d, 0, sizeof(d));

  for (int i=0; i<128; i++)
  {
    s[i][0]=src[i].le_half0();
    s[i][1]=src[i].le_half1();
  }

  for (int i=63; i>=0; i--)
  {
    uint64_t x = s[i][0];
    for (int j=0; j<64; j++) { d[j][0] = (x & 1) | (d[j][0]<<1);  x>>=1; }
  }

  for (int i=63; i>=0; i--)
  {
    uint64_t x = s[i][1];
    for (int j=64; j<128; j++) { d[j][0] = (x & 1) | (d[j][0]<<1); x>>=1; }
  }

  for (int i=127; i>=64; i--)
  {
    uint64_t x = s[i][0];
    for (int j=0; j<64; j++) { d[j][1] = (x & 1) | (d[j][1]<<1); x>>=1; }
  }

  for (int i=127; i>=64; i--)
  {
    uint64_t x = s[i][1];
    for (int j=64; j<128; j++) { d[j][1] = (x & 1) | (d[j][1]<<1); x>>=1; }
  }

  for (int i=0; i<128; i++)
  {
    dst[i]=buf128_t::make_le(d[i][0], d[i][1]);
  }
#endif
}


static void generate_key_blocks(bufs128_t& key_blocks, int blocks_count, uint64_t counter, crypto::ecb_aes_t ecb_keys[128])
{
  key_blocks.allocate(blocks_count*128);
  bufs128_t src(blocks_count);
  bufs128_t dst(blocks_count);
  
  for (int i=0; i<128; i++)
  {
    for (int b=0; b<blocks_count; b++) src[b] = buf128_t::make_le(counter + b*128);
    ecb_keys[i].update(mem_t(byte_ptr(src.data()), blocks_count*16), byte_ptr(dst.data()));
    for (int b=0; b<blocks_count; b++) key_blocks[b*128+i] = dst[b];
  }

  for (int b=0; b<blocks_count; b++)
  {
    buf128_t enc[128];
    for (int i=0; i<128; i++) enc[i] = key_blocks[b*128+i];
    transpose_128x128(key_blocks.data() + b*128, enc);
  }
}

static const byte_t fixed_aes_key[16] = { 0x1f, 0xc9, 0x4f, 0x81, 0x93, 0x55, 0x40, 0x85, 0xba, 0x4e, 0x7b, 0xb6, 0xb7, 0xcd, 0x73, 0xba };

class fixed_aes_openssl_key_t : public crypto::ecb_aes_t
{
public:
  fixed_aes_openssl_key_t() { encrypt_init(mem_t(fixed_aes_key, 16)); } 
};

static fixed_aes_openssl_key_t fixed_aes_openssl_key;

static void generate_128_m_hashes(buf128_t dst[128], uint64_t counter, buf128_t src[128])
{
  buf128_t pi_x[128];
  buf128_t pi_x_xor_i[128];
  mem_t x = mem_t(byte_ptr(src), 128*16);
  fixed_aes_openssl_key.update(x, byte_ptr(pi_x)); // calculate pi(x)

  for (int j=0; j<128; j++, counter++) 
  {
    buf128_t i = buf128_t::make_le(counter);
    pi_x_xor_i[j] = pi_x[j] ^ i ; // calculate pi(x) ^ i
  }

  fixed_aes_openssl_key.update(mem_t(byte_ptr(pi_x_xor_i), 128*16), byte_ptr(dst)); // calculate pi(pi(x) ^ i)
  for (int j=0; j<128; j++) dst[j] ^= pi_x[j]; // dst = pi(pi(x) ^ i) ^ pi(x)
}


#ifdef INTEL_X64
static void mul128_sse(__m128i a, __m128i b, __m128i *res1, __m128i *res2)
{
    __m128i tmp3, tmp4, tmp5, tmp6;

    tmp3 = _mm_clmulepi64_si128(a, b, 0x00);
    tmp4 = _mm_clmulepi64_si128(a, b, 0x10);
    tmp5 = _mm_clmulepi64_si128(a, b, 0x01);
    tmp6 = _mm_clmulepi64_si128(a, b, 0x11);

    tmp4 = _mm_xor_si128(tmp4, tmp5);
    tmp5 = _mm_slli_si128(tmp4, 8);
    tmp4 = _mm_srli_si128(tmp4, 8);
    tmp3 = _mm_xor_si128(tmp3, tmp5);
    tmp6 = _mm_xor_si128(tmp6, tmp4);
    // initial mul now in tmp3, tmp6
    *res1 = tmp3;
    *res2 = tmp6;
}

// reduce modulo x^128 + x^7 + x^2 + x + 1
// NB this is incorrect as it bit-reflects the result as required for
// GCM mode
static void gfred128_sse(__m128i tmp3, __m128i tmp6, __m128i *res)
{
    __m128i tmp2, tmp4, tmp5, tmp7, tmp8, tmp9;
    tmp7 = _mm_srli_epi32(tmp3, 31);
    tmp8 = _mm_srli_epi32(tmp6, 31);

    tmp3 = _mm_slli_epi32(tmp3, 1);
    tmp6 = _mm_slli_epi32(tmp6, 1);

    tmp9 = _mm_srli_si128(tmp7, 12);
    tmp8 = _mm_slli_si128(tmp8, 4);
    tmp7 = _mm_slli_si128(tmp7, 4);
    tmp3 = _mm_or_si128(tmp3, tmp7);
    tmp6 = _mm_or_si128(tmp6, tmp8);
    tmp6 = _mm_or_si128(tmp6, tmp9);

    tmp7 = _mm_slli_epi32(tmp3, 31);
    tmp8 = _mm_slli_epi32(tmp3, 30);
    tmp9 = _mm_slli_epi32(tmp3, 25);

    tmp7 = _mm_xor_si128(tmp7, tmp8);
    tmp7 = _mm_xor_si128(tmp7, tmp9);
    tmp8 = _mm_srli_si128(tmp7, 4);
    tmp7 = _mm_slli_si128(tmp7, 12);
    tmp3 = _mm_xor_si128(tmp3, tmp7);

    tmp2 = _mm_srli_epi32(tmp3, 1);
    tmp4 = _mm_srli_epi32(tmp3, 2);
    tmp5 = _mm_srli_epi32(tmp3, 7);
    tmp2 = _mm_xor_si128(tmp2, tmp4);
    tmp2 = _mm_xor_si128(tmp2, tmp5);
    tmp2 = _mm_xor_si128(tmp2, tmp8);
    tmp3 = _mm_xor_si128(tmp3, tmp2);

    tmp6 = _mm_xor_si128(tmp6, tmp3);
    *res = tmp6;
}

// Based on Intel's code for GF(2^128) mul, with reduction
static void gf_mul128_sse(__m128i a, __m128i b, __m128i *res)
{
    __m128i tmp3, tmp6;
    mul128_sse(a, b, &tmp3, &tmp6);
    // Now do the reduction
    gfred128_sse(tmp3, tmp6, res);
}

#else

// Multiplication in GF(2^128) 
static void gf_mul128_generic(const uint8_t *x, const uint8_t *y, uint8_t *z)
{
  uint8_t v[16];
  for (int i=0; i<16; i++) v[i] = y[15-i]; 

  uint8_t r[16] = {0};

  for (int i = 0; i < 16; i++) 
  {
		for (int j = 0; j < 8; j++) 
    {
			if (x[15-i] & (1 << (7 - j))) 
      {
        ((uint64_t *)r)[0] ^= ((uint64_t *)v)[0];
        ((uint64_t *)r)[1] ^= ((uint64_t *)v)[1];
      }
      
      uint8_t b = v[15] & 0x01;

	    uint64_t val = ub::be_get_8(v + 8);
	    val >>= 1;
	    if (v[7] & 1) val |= 0x8000000000000000;
	    ub::be_set_8(v + 8, val);

	    val = ub::be_get_8(v);
	    val >>= 1;
	    ub::be_set_8(v, val);

			if (b) v[0] ^= 0xe1;
		}
	}

  for (int i=0; i<16; i++) z[i] = r[15-i];
}

#endif

static buf128_t gf_mult(buf128_t x1, buf128_t x2)
{
  buf128_t res;
#ifdef INTEL_X64
  gf_mul128_sse(x1.value, x2.value, &res.value);
#else
  gf_mul128_generic(const_byte_ptr(x1), const_byte_ptr(x2), byte_ptr(res));
#endif
  return res;
}

static ub::bufs128_t ot_ext_calculate_prf(int blocks_count, buf256_t u_hash)
{
  ub::bufs128_t X(blocks_count*128); X.mem().bzero();

  crypto::ctr_aes_t ctr_key;
  ctr_key.init(u_hash.lo, u_hash.hi);
  ctr_key.update(X.mem(), (byte_ptr)X.data());
  return X;
}

void ot_extend_t::rec_step1(int blocks_count, ot_receiver_t& rec, message1_t& out)
{
  rec.index = 0;
  rec.blocks.resize(blocks_count);

  bufs128_t t0, t1;

  generate_key_blocks(t0, blocks_count, rec.counter, rec.ecb_keys_t0);
  generate_key_blocks(t1, blocks_count, rec.counter, rec.ecb_keys_t1);

  buf128_t all_one = ~buf128_t(0);

  out.u.allocate(blocks_count*128);
  for (int b=0; b<blocks_count; b++)
  {
    ot_receiver_block_t& block = rec.blocks[b];
    block.rnd = buf128_t::rand();

    // generate u
    for (int i=0; i<128; i++)
    {
      out.u[b*128+i] = t0[b*128+i] ^ t1[b*128+i];
      bool x = block.rnd.get_bit(i);
      if (x) out.u[b*128+i] ^= all_one;
    }
  }

  buf256_t u_hash = sha256_t::hash(out.u);
  ub::bufs128_t X = ot_ext_calculate_prf(blocks_count, u_hash);

  out.x = out.t = 0;

  for (int b=0; b<blocks_count; b++)
  {
    ot_receiver_block_t& block = rec.blocks[b];    

    buf128_t src[128];
    for (int i=0; i<128; i++) 
    {
      buf128_t t0i = src[i] = t0[b*128+i];
      buf128_t Xi = X[b*128 + i];

      bool xj = block.rnd.get_bit(i);     
      if (xj) out.x ^= Xi;

      out.t ^= gf_mult(t0i, Xi);
    }

    generate_128_m_hashes(block.mb, rec.counter + b*128, src);
  }

  // skip first 192 lines
  rec.index += 192;
  rec.counter += 192;
}

error_t ot_extend_t::snd_step2(int blocks_count, ot_sender_t& snd, const message1_t& in)
{
  error_t rv = 0;
  snd.index = 0;
  snd.blocks.resize(blocks_count);

  ub::bufs128_t tb;
  generate_key_blocks(tb, blocks_count, snd.counter, snd.ecb_keys_tb);

  ub::bufs128_t q;
  q.allocate(blocks_count * 128);

  for (int b=0; b<blocks_count; b++)
  {
    ot_sender_block_t& block = snd.blocks[b];
    for (int i=0; i<128; i++) q[b*128+i]  = (snd.delta & in.u[b*128+i]) ^ tb[b*128+i];
  }

  buf256_t u_hash = sha256_t::hash(in.u);
  ub::bufs128_t X = ot_ext_calculate_prf(blocks_count, u_hash);

  buf128_t Q = 0;

  for (int b=0; b<blocks_count; b++)
  {
    ot_sender_block_t& block = snd.blocks[b];

    buf128_t src0[128];
    buf128_t src1[128];
    for (int i=0; i<128; i++) 
    {
      buf128_t temp  = q[b*128+i];
      src0[i] = temp;
      src1[i] = temp ^ snd.delta;

      buf128_t Xi = X[b*128 + i];
      Q ^= gf_mult(Xi, q[b*128+i]);
    }

    generate_128_m_hashes(block.m0, snd.counter + b*128, src0);
    generate_128_m_hashes(block.m1, snd.counter + b*128, src1);

  }

  if (in.t != (Q ^ gf_mult(in.x, snd.delta)))
  {
    return rv = ub::error(E_CRYPTO);
  }
  
  // skip first 192 lines
  snd.index += 192;
  snd.counter += 192;
  return rv;
}

// -------------------------------- OT one of two ------------------------------

void ot_sender_t::get_info(ot_sender_info_t& info)
{
  int row = index / 128;
  int col = index % 128;
  assert(row<(int)blocks.size());
  ot_sender_block_t& block = blocks[row];

  info.m0 = block.m0[col];
  info.m1 = block.m1[col];

  index++;
  counter++;
}

bool ot_receiver_t::get_info(bool b, ot_receiver_info_t& info)
{
  int row = index / 128;
  int col = index % 128;
  assert(row<(int)blocks.size());
  ot_receiver_block_t& block = blocks[row];

  info.r = block.rnd.get_bit(col);
  bool cc = b ^ info.r;
  info.mb = block.mb[col];

  index++;
  counter++;
  return cc;
}

static void fixed_key_encrypt_with_additional_key(buf128_t additional_key, mem_t src, byte_ptr dst)
{
  int blocks = (src.size + AES_BLOCK_SIZE - 1) / AES_BLOCK_SIZE;
  ub::bufs128_t counters(blocks);
  ub::bufs128_t encrypted(blocks);
  
  for (int i=0; i<blocks; i++) counters[i] = additional_key ^ buf128_t::make_le(i);
  fixed_aes_openssl_key.update(counters.mem(), (byte_ptr)encrypted.data());
  for (int i=0; i<blocks; i++) encrypted[i] ^= counters[i];

  for (int i=0; i<src.size; i++) dst[i] = src[i] ^ encrypted.mem()[i];
}

void ot_sender_info_t::prepare_one_of_two(bool c, mem_t x0, mem_t x1, byte_ptr out)
{
  byte_t iv[AES_BLOCK_SIZE] = {0};
  
  assert(x0.size==x1.size);
  int d_size = x0.size;

  fixed_key_encrypt_with_additional_key(m0, c ? x1 : x0, out);
  fixed_key_encrypt_with_additional_key(m1, c ? x0 : x1, out+d_size);
}

buf_t ot_sender_info_t::prepare_one_of_two(bool c, mem_t x0, mem_t x1)
{
  buf_t out(x0.size*2);
  prepare_one_of_two(c, x0, x1, out.data());
  return out;
}

void ot_receiver_info_t::get_one_of_two(mem_t in, byte_ptr out)
{
  byte_t iv[AES_BLOCK_SIZE] = {0};
  int out_size = in.size / 2;
  int offset = r ? out_size : 0;
  mem_t src = mem_t(in.data + offset, out_size);

  fixed_key_encrypt_with_additional_key(mb, src, out);
}

buf_t ot_receiver_info_t::get_one_of_two(mem_t in)
{
  buf_t out(in.size/2);
  get_one_of_two(in, out.data());
  return out;
}



} // namespace mpc
