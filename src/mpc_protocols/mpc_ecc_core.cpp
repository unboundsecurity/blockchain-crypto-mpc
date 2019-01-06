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
#include "mpc_ecc_core.h"

using namespace ub;
using namespace crypto;

namespace mpc {

const int ZK_PAILLIER_alpha = 6370;
const int ZK_PAILLIER_m2 = 11;

buf_t ZK_PAILLIER_P_non_interactive(const bn_t& N, const bn_t& phi_N, mem_t session_id)
{
  int N_len = N.get_bin_size();
  buf_t out(N_len*ZK_PAILLIER_m2);

  bn_t N_inv = bn_t::inverse_mod(N, phi_N);

  buf256_t seed = sha256_t::hash(N, session_id);

  crypto::ctr_aes_t ctr; 
  ctr.init(seed.lo, buf128_t(0));

  int enc_len = N_len/16+2;
  buf_t enc(enc_len); 

  int offset = 0;
  for (int i=0; i<ZK_PAILLIER_m2; i++, offset+=N_len)
  {
    enc.bzero();
    ctr.update(enc, enc.data());
    bn_t rho = bn_t::from_bin(enc);
    rho %= N;
    bn_t sigma = rho.pow_mod(N_inv, N);
    sigma.to_bin(out.data()+offset, N_len);
  }

  return out;
}

bool ZK_PAILLIER_V_non_interactive(const bn_t& N, mem_t pi, mem_t session_id)
{
  for (int i=0; ; i++)
  {
    int small_prime = small_primes[i];
    if (small_prime>ZK_PAILLIER_alpha) break;
    if ((N % small_prime)==0)
    {
      return false;
    }
  }

  int N_len = N.get_bin_size();
  if (pi.size != N_len*ZK_PAILLIER_m2)
  {
    return false;
  }

  buf256_t seed = sha256_t::hash(N, session_id);

  crypto::ctr_aes_t ctr; 
  ctr.init(seed.lo, buf128_t(0));

  int enc_len = N_len/16+2;
  buf_t enc(enc_len); 

  int offset = 0;
  for (int i=0; i<ZK_PAILLIER_m2; i++, offset+=N_len)
  {
    enc.bzero();
    ctr.update(enc, enc.data());
    bn_t rho = bn_t::from_bin(enc);
    rho %= N;
    bn_t sigma = bn_t::from_bin(mem_t(pi.data+offset, N_len));
    if (rho != sigma.pow_mod(N, N))
    {
      return false;
    }
  }

  return true;
}


//----------------------------------- zk_paillier_zero_t ---------------------------

void zk_paillier_zero_t::p(const bn_t& N, const bn_t& c, mem_t session_id, uint8_t aux, const bn_t& r)
{
  bn_t N2 = N*N;
  bn_t rho = bn_t::rand(N);
  bn_t a = rho.pow_mod(N, N2);
  
  e = bn_t(sha256_t::hash(N, c, a, session_id, aux));
  MODULO(N2) z = rho * r.pow(e);
}

bool zk_paillier_zero_t::v(const bn_t& N, const bn_t& c, mem_t session_id, uint8_t aux) const
{
  bn_t N2 = N*N;
  bn_t a;
  MODULO(N2) a = z.pow(N) / c.pow(e);

  if (bn_t::gcd(a, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(c, N) != 1) 
  {
    return false;
  }

  if (bn_t::gcd(z, N) != 1) 
  {
    return false;
  }

  bn_t e_tag = bn_t(sha256_t::hash(N, c, a, session_id, aux));
  return e==e_tag;
}

//------------- zk_paillier_range_t ---------------------------------------

struct paillier_enc_info_t
{
  const bn_t* src;
  const bn_t* rand;
  bn_t* dst;
};

class paillier_enc_thread_t : public ub::thread_t
{
public:
  virtual void run() override
  {
    int n = (int)infos.size();
    for (int i=0; i<n; i++) *infos[i].dst = paillier->encrypt(*infos[i].src, *infos[i].rand);
  }

  void add(const bn_t* src, const bn_t* rand, bn_t* dst)
  {
    paillier_enc_info_t info; info.src = src; info.rand = rand; info.dst = dst;
    infos.push_back(info);
  }
  void set_paillier(const crypto::paillier_t& paillier)
  {
    this->paillier = &paillier;
  }

private:
  std::vector<paillier_enc_info_t> infos;
  const crypto::paillier_t* paillier;
};

int zk_paillier_range_time = 0;


void zk_paillier_range_t::p(bool threaded, const bn_t& q, const crypto::paillier_t& paillier, const bn_t& c_key, mem_t session_id, uint8_t aux, const bn_t& x_original, const bn_t& r)
{
  int tt = GetTickCount();

  bn_t N = paillier.get_N();
  bn_t x = x_original;
  bn_t l = q / 3;
  bn_t l2 = l * 2;
  bn_t l3 = l * 3;

  bn_t w1[t];
  bn_t w2[t];
  bn_t c1[t];
  bn_t c2[t];
  bn_t r1[t];
  bn_t r2[t];
  buf128_t rnd = buf128_t::rand();

  for (int i=0; i<t; i++) 
  {
    w2[i] = bn_t::rand(l);
    w1[i] = l + w2[i];

    if (rnd.get_bit(i)) 
    {
      std::swap(w1[i], w2[i]);
    }

    r1[i] = bn_t::rand(N);
    r2[i] = bn_t::rand(N);
  }

  int cores = threaded ? ub::get_cpu_count() : 1;
  if (cores<1) cores = 1;
  std::vector<paillier_enc_thread_t> threads(cores);

  for (int i=0; i<t; i++) 
  {
    int thread_index = i % cores;
    threads[thread_index].add(w1+i, r1+i, c1+i);
    threads[thread_index].add(w2+i, r2+i, c2+i);
  }

  for (int i=0; i<cores; i++) threads[i].set_paillier(paillier);
  for (int i=0; i<cores-1; i++) threads[i].start();
  threads[cores-1].run();
  for (int i=0; i<cores-1; i++) threads[i].join();

  /*for (int i=0; i<t; i++) 
  {
    c1[i] = paillier.encrypt(w1[i], r1[i]);
    c2[i] = paillier.encrypt(w2[i], r2[i]);
  }*/


  sha256_t sha256;
  for (int i=0; i<t; i++) 
  {
    sha256.update(c1[i]);
    sha256.update(c2[i]);
  }

  u = 0;

       if (x < l)  u = 0;
  else if (x < l2) u = 1;
  else if (x < l3) u = 2;
  else if (x < q)  u = 3;
  else assert(false);

  bn_t c = paillier.sub_scalar(c_key, l * u);
  x = x - (l * u);
  
  sha256.update(u);
  sha256.update(c_key);
  sha256.update(N);
  sha256.update(session_id);
  sha256.update(aux);

  e = sha256.final().lo; // 16 bytes

  for (int i=0; i<t; i++) 
  {
    bool ei = e.get_bit(i);
    if (!ei)
    {
      infos[i].a = w1[i];
      infos[i].b = r1[i];
      infos[i].c = w2[i];
      infos[i].d = r2[i];
    }
    else
    {
      int j = 0;
           if (x + w1[i] >= l && x + w1[i] <= l2) j = 1;
      else if (x + w2[i] >= l && x + w2[i] <= l2) j = 2;
      else assert(false);

      infos[i].a = j;
      infos[i].b = x + ((j==1) ? w1[i] : w2[i]);
      MODULO(N) infos[i].c = r * ((j==1) ? r1[i] : r2[i]);
      infos[i].d = (j==2) ? c1[i] : c2[i];
    }
  }

  zk_paillier_range_time += GetTickCount()-tt;
}

bool zk_paillier_range_t::v(bool threaded, const bn_t& q, const bn_t& N, const bn_t& c_key, mem_t session_id, uint8_t aux) const
{
  int tt = GetTickCount();
  bn_t N2 = N*N;

  bn_t l = q / 3;
  bn_t l2 = l * 2;

  crypto::paillier_t paillier; paillier.create_pub(N);
  bn_t c = paillier.sub_scalar(c_key, l * u);
  int j;

  int cores = threaded ? ub::get_cpu_count() : 1;
  if (cores<1) cores = 1;
  std::vector<paillier_enc_thread_t> threads(cores);

  bn_t c1_tab[t];
  bn_t c2_tab[t];
  //bn_t c_tag_tab[t];

  for (int i=0; i<t; i++) 
  {
    //bn_t c1, c2;
    int thread_index = i % cores;

    bool ei = e.get_bit(i);
    if (!ei)
    {
      bn_t w1 = infos[i].a;
      bn_t w2 = infos[i].c;
      if (w1<w2)
      {
        if (w1<0) return false;
        if (w1>l) return false;
        if (w2<l) return false;
        if (w2>l2) return false;
      }
      else
      {
        if (w2<0) return false;
        if (w2>l) return false;
        if (w1<l) return false;
        if (w1>l2) return false;
      }

      //bn_t r1 = infos[i].b;
      //bn_t r2 = infos[i].d;
      //c1 = paillier.encrypt(w1, r1);
      //c2 = paillier.encrypt(w2, r2);
      threads[thread_index].add(&infos[i].a, &infos[i].b, &c1_tab[i]); 
      threads[thread_index].add(&infos[i].c, &infos[i].d, &c2_tab[i]); 
    }
    else
    {
      if (infos[i].a!=1 && infos[i].a!=2) return false;
      j = (int)infos[i].a;

      bn_t wi = infos[i].b;
      if (wi<l) return false;
      if (wi>l2) return false;

      //bn_t ri = infos[i].c;
      //bn_t c_tag = paillier.encrypt(wi, ri);
      threads[thread_index].add(&infos[i].b, &infos[i].c, &c1_tab[i]); 
    }
  }

  for (int i=0; i<cores; i++) threads[i].set_paillier(paillier);
  for (int i=0; i<cores-1; i++) threads[i].start();
  threads[cores-1].run();
  for (int i=0; i<cores-1; i++) threads[i].join();

  sha256_t sha256;
  for (int i=0; i<t; i++) 
  {
    bn_t c1, c2;

    bool ei = e.get_bit(i);
    if (!ei)
    {
      c1 = c1_tab[i];
      c2 = c2_tab[i];
    }
    else
    {
      j = (int)infos[i].a;

      MODULO(N2) c1 = c1_tab[i] / c;
      c2 = infos[i].d;

      if (j==2) std::swap(c1, c2);
    }

    sha256.update(c1);
    sha256.update(c2);
  }

  sha256.update(u);
  sha256.update(c_key);
  sha256.update(N);
  sha256.update(session_id);
  sha256.update(aux);

  buf128_t e_tag = sha256.final().lo; // 16 bytes
  if (e != e_tag)
  {
    return false;
  }

  zk_paillier_range_time += GetTickCount()-tt;
  return true;
}

//-------------------------------------- zk_pdl_t ------------------------------
void zk_pdl_t::p(ecurve_t curve, const ecc_point_t& Q, const bn_t& c_key, const paillier_t& paillier, mem_t session_id, uint8_t aux, const bn_t& r_key, const bn_t& x1)
{
  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();
 
  bn_t N = paillier.get_N();
  bn_t r = bn_t::rand(q);
  bn_t r_rand = bn_t::rand(N);					//(*)
  c_r = paillier.encrypt(r,r_rand);				//(*)
  R = G * r;
  bn_t rho = bn_t::rand(q.sqr());
  bn_t rho_rand = bn_t::rand(N);				//(*)
  c_rho =  paillier.encrypt(rho*q, rho_rand);			//(*)
 
  bn_t e = bn_t(sha256_t::hash(c_key, N, Q, c_r, R, c_rho, session_id, aux));
  bn_t temp = paillier.mul_scalar(c_key, e);
  bn_t temp2 = paillier.add_ciphers(c_r, temp);
  bn_t c_z = paillier.add_ciphers(temp2, c_rho);
  z = r + (e * x1) + (rho * q);
 
  bn_t c_tag = paillier.sub_scalar(c_z, z);
 
  bn_t r_temp = r_key.pow_mod(e, N);				//(*)
  bn_t r_tag;
  MODULO(N) r_tag = r_temp * r_rand * rho_rand;		//(*)
 
  zk_paillier_zero.p(N, c_tag, session_id, aux, r_tag);
 
  zk_paillier_range.p(true, q, paillier, c_key, session_id, aux, x1, r_key);
}


bool zk_pdl_t::v(ecurve_t curve, const ecc_point_t& Q, const bn_t& c_key, const bn_t& N, mem_t session_id, uint8_t aux) const
{
  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  paillier_t paillier; paillier.create_pub(N);

  bn_t e = bn_t(sha256_t::hash(c_key, N, Q, c_r, R, c_rho, session_id, aux));

  bn_t temp = paillier.mul_scalar(c_key, e);
  bn_t temp2 = paillier.add_ciphers(c_r, temp);
  bn_t c_z = paillier.add_ciphers(temp2, c_rho);

  ecc_point_t P = G*z;
  if (P != R + Q*e) 
  {
    return false;
  }
  if (z<0 || z>=N) 
  {
    return false;
  }

  bn_t c_tag = paillier.sub_scalar(c_z, z);

  if (!zk_paillier_zero.v(N, c_tag, session_id, aux)) 
  {
    return false;
  }


  if (!zk_paillier_range.v(true, q, N, c_key, session_id, aux)) 
  {
    return false;
  }
  return true;
}


// ------------------------------ zk_dl ------------------------

static bn_t zk_dl_hash(const ecc_point_t& G, const ecc_point_t& Q, const ecc_point_t& X, mem_t session_id, uint8_t aux)
{
  return bn_t(sha256_t::hash(G, Q, X, session_id, aux));
}


void zk_dl_t::p(ecurve_t curve, const ecc_point_t& Q, mem_t session_id, uint8_t aux, const bn_t& d)
{
  const bn_t& order = curve.order();
	bn_t sigma = bn_t::rand(order);
  const ecc_generator_point_t& G = curve.generator();
  ecc_point_t X = G * sigma;

  e = zk_dl_hash(G, Q, X, session_id, aux);
	
  MODULO(order)
  {
    u = e * d + sigma;
  }
}

bool zk_dl_t::v(ecurve_t curve, const ecc_point_t& Q, mem_t session_id, uint8_t aux) const
{
  assert(curve.check(Q));

  const ecc_generator_point_t& G = curve.generator();
  ecc_point_t X = G * u - Q * e;

  bn_t etag = zk_dl_hash(G, Q, X, session_id, aux);
  if (etag != e)
  {
    return false;
  }
  return true;
}


// ------------------------------ zk_ddh ------------------------

static buf_t hash_zk_ddh(
  const ecc_point_t& G, 
  const ecc_point_t& Q, 
  const ecc_point_t& A, 
  const ecc_point_t& B, 
  const ecc_point_t& X, 
  const ecc_point_t& Y, 
  mem_t session_id,
  uint8_t aux)
{
  return sha256_t::hash(G, Q, A, B, X, Y, session_id, aux);
}

void zk_ddh_t::p(
  ecurve_t curve, 
  const ecc_point_t& Q, 
  const ecc_point_t& A, 
  const ecc_point_t& B, 
  const bn_t& w, 
  mem_t session_id,
  uint8_t aux)  // output
{
  const ecc_generator_point_t& G = curve.generator();
  bn_t sigma = curve.get_random_value();
  
  ecc_point_t X = G * sigma;
  ecc_point_t Y = Q * sigma;

  e_buf = hash_zk_ddh(G, Q, A, B, X, Y, session_id, aux);
  bn_t e = bn_t::from_bin(e_buf);
  const bn_t& order = curve.order();
  
  MODULO(order)  { u = sigma + e * w; }
}

bool zk_ddh_t::v(
  ecurve_t curve, 
  const ecc_point_t& Q, 
  const ecc_point_t& A,
  const ecc_point_t& B, 
  mem_t session_id,
  uint8_t aux) const
{
  const ecc_generator_point_t& G = curve.generator();
  bn_t e = bn_t::from_bin(e_buf);

  ecc_point_t X = G * u - A * e;
  ecc_point_t Y = Q * u - B * e;

  buf_t h = hash_zk_ddh(G, Q, A, B, X, Y, session_id, aux);
  return secure_equ(h, e_buf);
}



//----------------------------- zk_paillier_eq_t -----------------

void zk_paillier_eq_t::p(
  const bn_t& x, const bn_t& r1, const bn_t& r2,     
  mem_t session_id,
  const bn_t& n1,     
  const bn_t& c1,     
  const bn_t& n2,
  const bn_t& c2)
{
  this->c1 = c1;
  this->c2 = c2;
  paillier_t paillier1; paillier1.create_pub(n1);
  paillier_t paillier2; paillier2.create_pub(n2);

  bn_t mod1 = n1*n1;
  bn_t mod2 = n2*n2;
    
  bn_t alpha = bn_t::rand(n1 + n2);
  bn_t d1  = bn_t::rand(n1);
  bn_t d2  = bn_t::rand(n2);

  s1 = paillier1.encrypt(alpha, d1);
  s2 = paillier2.encrypt(alpha, d2);

  bn_t e = bn_t(sha256_t::hash(n1, n2, c1, c2, s1, s2, session_id));

  lc = alpha + e * x;
  MODULO(mod1) t1 = d1 * r1.pow(e);
  MODULO(mod2) t2 = d2 * r2.pow(e);
}

bool zk_paillier_eq_t::v(
  mem_t session_id,
  const bn_t& n1,     
  const bn_t& n2) const
{
  paillier_t paillier1; paillier1.create_pub(n1);
  paillier_t paillier2; paillier2.create_pub(n2);

  bn_t mod1 = n1*n1;
  bn_t mod2 = n2*n2;

  bn_t e = bn_t(sha256_t::hash(n1, n2, c1, c2, s1, s2, session_id));

  bn_t v1 = paillier1.encrypt(lc, t1);
  bn_t v2 = paillier2.encrypt(lc, t2);

  bn_t v1_test, v2_test;
  MODULO(mod1) v1_test =  s1 * c1.pow(e);
  MODULO(mod2) v2_test =  s2 * c2.pow(e);

  if (v1 != v1_test) 
  {
    return false;
  }

  if (v2 != v2_test) 
  {
    return false;
  }

  return true;
}


// ----------------- zk_ec_affine_t ----------------
void zk_ec_affine_t::p(const ecc_point_t& P, const ecc_point_t& U, const ecc_point_t& V, const ecc_point_t& U_tag, const ecc_point_t& V_tag, mem_t session_id, const bn_t& s, const bn_t& w, const bn_t& r_tag)
{
  ecurve_t curve = crypto::curve_p256;
  assert(P.get_curve()==curve);
  assert(U.get_curve()==curve);
  assert(V.get_curve()==curve);
  assert(U_tag.get_curve()==curve);
  assert(V_tag.get_curve()==curve);

  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  bn_t alpha = curve.get_random_value();
  bn_t beta  = curve.get_random_value();
  bn_t gamma = curve.get_random_value();

  ecc_point_t A = G * alpha + U * beta;
  ecc_point_t B = P * alpha + V * beta + G * gamma;

  buf256_t hash = sha256_t::hash(P, U, V, U_tag, V_tag, A, B, session_id);
  e = bn_t(hash.lo);

  MODULO(q)
  {
    z1 = alpha + e * r_tag;
    z2 = beta + e * s;
    z3 = gamma + e * w;
  }
}

bool zk_ec_affine_t::v(const ecc_point_t& P, const ecc_point_t& U, const ecc_point_t& V, const ecc_point_t& U_tag, const ecc_point_t& V_tag, mem_t session_id) const
{
  ecurve_t curve = crypto::curve_p256;
  assert(P.get_curve()==curve);
  assert(U.get_curve()==curve);
  assert(V.get_curve()==curve);
  assert(U_tag.get_curve()==curve);
  assert(V_tag.get_curve()==curve);

  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();

  ecc_point_t A = G * z1 + U * z2 - U_tag * e;
  ecc_point_t B = P * z1 + V * z2 + G * z3 - V_tag * e;

  buf256_t hash = sha256_t::hash(P, U, V, U_tag, V_tag, A, B, session_id);
  bn_t e_tag = bn_t(hash.lo);

  if (e_tag != e)
  {
    return false;
  }

  return true;
}


// --------------------------------------------------- equality_test_t -----------------

struct equality_test_private_key_t
{
  equality_test_private_key_t();
  ecc_point_t P;
  bn_t x;
  zk_dl_t zk_dl;
};
ub::global_t<equality_test_private_key_t> g_equality_test_private_key;

equality_test_private_key_t::equality_test_private_key_t()
{
  ecurve_t curve = crypto::curve_p256;
  const ecc_generator_point_t& G = curve.generator();
  x = curve.get_random_value();
  P = G * x;
  zk_dl.p(curve, P, mem_t(), 0, x);
}

struct equality_test_public_key_t
{
  ub::mutex_t lock;
  ecc_point_t P;
};
ub::global_t<equality_test_public_key_t> g_equality_test_public_key;


void equality_test_t::peer1_step1(message1_t& out)
{
  const equality_test_private_key_t& prv_key = g_equality_test_private_key.instance();

  ecurve_t curve = crypto::curve_p256;
  const bn_t& q = curve.order();
  const ecc_generator_point_t& G = curve.generator();
  bn_t a = bn_t(value_hash) % q;

  bn_t r = curve.get_random_value();
  out.zk_dl = prv_key.zk_dl;
  out.P = prv_key.P;
  out.U = U = G * r;
  out.V = V = out.P * r - G * a;
}

error_t equality_test_t::peer2_step1(const message1_t& in, message2_t& out)
{
  error_t rv = 0;
  ecurve_t curve = crypto::curve_p256;
  const bn_t& q = curve.order();

  const ecc_generator_point_t& G = curve.generator();
  if (!curve.check(in.U)) return ub::error(E_BADARG);
  if (!curve.check(in.V)) return ub::error(E_BADARG);

  equality_test_public_key_t& pub_key = g_equality_test_public_key.instance();
  ecc_point_t P;
  {
    ub::scoped_lock_t scoped(pub_key.lock);
    if (pub_key.P.valid()) P = pub_key.P;
  }

  if (!P.valid() || P != in.P)
  {
    if (!curve.check(in.P)) return rv = ub::error(E_BADARG);
    if (!in.zk_dl.v(curve, in.P, mem_t(), 0)) return rv = ub::error(E_BADARG);

    ub::scoped_lock_t scoped(pub_key.lock);
    pub_key.P = P = in.P;
  }

  bn_t s = curve.get_random_value();
  t = curve.get_random_value();
  bn_t r_tag = curve.get_random_value();
  bn_t b = bn_t(value_hash) % q;

  out.V_tag = ((in.V + G * b) * s) + (P * r_tag) + (G * t);
  out.U_tag = in.U * s + G * r_tag;

  bn_t w;
  MODULO (q) w = t + s * b;

  out.zk_ec_affine.p(P, in.U, in.V, out.U_tag, out.V_tag, mem_t(), s, w, r_tag);

  ecc_point_t P_tag = G * t;

  out.hash = sha256_t::hash(P_tag, value_hash);
  return rv;
}

error_t equality_test_t::peer1_step2(const message2_t& in, message3_t& out, bool& result)
{
  error_t rv = 0;

  ecurve_t curve = crypto::curve_p256;
  const bn_t& q = curve.order();

  if (!curve.check(in.U_tag)) return rv = ub::error(E_BADARG);
  if (!curve.check(in.V_tag)) return rv = ub::error(E_BADARG);

  const equality_test_private_key_t& prv_key = g_equality_test_private_key.instance();
  ecc_point_t P = prv_key.P;

  if (!in.zk_ec_affine.v(P, U, V, in.U_tag, in.V_tag, mem_t())) return rv = ub::error(E_BADARG);

  ecc_point_t P_tag = in.V_tag - in.U_tag * prv_key.x;

  buf256_t hash_tag = sha256_t::hash(P_tag, value_hash);
  result = (hash_tag == in.hash);
  if (result) out.P_tag = P_tag;

  return 0;
}

error_t equality_test_t::peer2_step2(const message3_t& in, bool& result)
{
  error_t rv = 0;
  result = false;

  if (!in.P_tag.valid())
  {
    return 0;
  }

  ecurve_t curve = crypto::curve_p256;
  const ecc_generator_point_t& G = curve.generator();
  if (!curve.check(in.P_tag)) return rv = ub::error(E_BADARG);

  if (in.P_tag != G * t) return rv = ub::error(E_CRYPTO);

  result = true;
  return 0;
}

} //namespace mpc