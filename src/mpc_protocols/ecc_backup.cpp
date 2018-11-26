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
#include "ecc_backup.h"


namespace ec_backup {

static const int security_param = 128;

static bn_t rsa_enc_oaep_with_seed(const crypto::rsa_key_t& pub_key, const bn_t& in, mem_t seed)
{
  int key_size = pub_key.size();
  buf_t temp(key_size);
  buf_t enc(key_size);
  buf_t input = in.to_bin();

  const EVP_MD* md = EVP_sha256();
  
  int rv = crypto::rsa_key_t::RSA_padding_add_PKCS1_OAEP_ex(
    temp.data(), key_size, 
    input.data(), input.size(),
    nullptr, 0, 
    md, md, seed.data, seed.size);
  if (rv<=0) return 0;

  if (!pub_key.encrypt_raw(temp.data(), enc.data())) return 0;
  return bn_t::from_bin(enc);
}

static bool get_bit(mem_t mem, int index)
{
  int byte_index = index / 8;
  int bit_index = index & 7;
  byte_t b = mem[byte_index];
  return ((b >> bit_index) & 1) != 0;
}


class ecurve_25519_t
{
public:
  typedef ecp_gen_25519_t generator_t;
  typedef ecp_25519_t point_t;
  bn_t order() const { return crypto::ec25519::order(); }
  generator_t generator() const { return crypto::ec25519::generator(); }
  bn_t rand() const { return crypto::ec25519::rand(); }
  point_t& get_Q_share(party_backup_material_t& party_backup_material) const { return party_backup_material.Q_share_25519; }
  const point_t& get_Q_share(const party_backup_material_t& party_backup_material) const { return party_backup_material.Q_share_25519; }
};

class ecurve_openssl_t
{
public:
  ecurve_openssl_t(ecurve_t _curve) : curve(_curve) {}

  typedef ecc_generator_point_t generator_t;
  typedef ecc_point_t point_t;

  bn_t order() const { return curve.order(); }
  generator_t generator() const { return curve.generator(); }
  bn_t rand() const { return curve.get_random_value(); }
  point_t& get_Q_share(party_backup_material_t& party_backup_material) const { return party_backup_material.Q_share; }
  const point_t& get_Q_share(const party_backup_material_t& party_backup_material) const { return party_backup_material.Q_share; }

private:
  ecurve_t curve;
};

template<class ECURVE>
static error_t generate_backup_proofs(const ECURVE& ecurve, const crypto::rsa_key_t& pub_key, const bn_t& x_share, backup_proofs_t& backup_proofs)
{
  error_t rv = 0;
  backup_proofs.proofs.resize(security_param);

  sha256_t sha256;

  bn_t q = ecurve.order();
  typename ECURVE::generator_t G = ecurve.generator();

  typename ECURVE::point_t Q = G * x_share;
  sha256.update(Q);
  
  std::vector<bn_t> cc0, cc1, rr, yy;
  std::vector<buf_t> ss0, ss1;
  ss0.resize(security_param);
  ss1.resize(security_param);
  cc0.resize(security_param);
  cc1.resize(security_param);
  rr.resize(security_param);
  yy.resize(security_param);

  for (int j=0; j<security_param; j++)
  {
    bn_t r = ecurve.rand();
    buf_t s0 = crypto::gen_random(32);
    buf_t s1 = crypto::gen_random(32);
    bn_t y = (x_share + r) % q;

    bn_t c0 = rsa_enc_oaep_with_seed(pub_key, r, s0);
    if (c0==0) return rv = ub::error(E_CRYPTO);
    bn_t c1 = rsa_enc_oaep_with_seed(pub_key, y, s1);
    if (c1==0) return rv = ub::error(E_CRYPTO);

    sha256.update(c0);
    sha256.update(c1);

    typename ECURVE::point_t Q_tag = G * r;
    sha256.update(Q_tag);

    rr[j] = r;
    yy[j] = y;
    cc0[j] = c0;
    cc1[j] = c1;
    ss0[j] = s0;
    ss1[j] = s1;
  }

  backup_proofs.proof_e = sha256.final();
  backup_proofs.proof_e.resize(16, true);

  for (int j=0; j<security_param; j++)
  {
    bool ej = get_bit(backup_proofs.proof_e, j);
    if (!ej)
    {
      backup_proofs.proofs[j].s = ss0[j];
      backup_proofs.proofs[j].c = cc1[j];
      backup_proofs.proofs[j].ry = rr[j];
    }
    else
    {
      backup_proofs.proofs[j].s = ss1[j];
      backup_proofs.proofs[j].c = cc0[j];
      backup_proofs.proofs[j].ry = yy[j];
    }
  }
  return rv;
}

error_t generate_backup_proofs(const crypto::rsa_key_t& pub_key, ecurve_t curve, const bn_t& x_share, backup_proofs_t& backup_proofs)
{
  ecurve_openssl_t ecurve(curve);
  return generate_backup_proofs(ecurve, pub_key, x_share, backup_proofs);
}

template<class ECURVE>
static error_t verify_backup_proofs(const ECURVE& ecurve, const crypto::rsa_key_t& pub_key, const typename ECURVE::point_t& Q_share, const backup_proofs_t& backup_proofs)
{
  error_t rv = 0;
  typename ECURVE::generator_t G = ecurve.generator();

  sha256_t sha256; 
  sha256.update(Q_share);

  for (int j=0; j<security_param; j++)
  {
    bool ej = get_bit(backup_proofs.proof_e, j);
    bn_t c0, c1;
    typename ECURVE::point_t Q_tag;

    const bn_t& ry = backup_proofs.proofs[j].ry;
    const bn_t& c = backup_proofs.proofs[j].c;
    const buf_t& s = backup_proofs.proofs[j].s;

    if (!ej)
    {
      c0 = rsa_enc_oaep_with_seed(pub_key, ry, s);
      Q_tag = G * ry;
      c1 = c;
    }
    else
    {
      c1 = rsa_enc_oaep_with_seed(pub_key, ry, s);
      Q_tag = G * ry - Q_share;
      c0 = c;
    }

    sha256.update(c0);
    sha256.update(c1);
    sha256.update(Q_tag);
  }

  buf_t e = sha256.final();
  e.resize(16, true);

  if (e!=backup_proofs.proof_e) return rv = ub::error(E_CRYPTO);
  return rv;
}

error_t verify_backup_proofs(const crypto::rsa_key_t& pub_key, const ecc_point_t& Q_share, const backup_proofs_t& backup_proofs)
{
  ecurve_openssl_t ecurve(Q_share.get_curve());
  return verify_backup_proofs(ecurve, pub_key, Q_share, backup_proofs);
}

static bn_t rsa_dec_oaep(const crypto::rsa_key_t& prv_key, const bn_t& in)
{
  int size = prv_key.size();
  buf_t out;
  if (!prv_key.decrypt_oaep(in.to_bin(size), crypto::hash_e::sha256, crypto::hash_e::sha256, mem_t(), out)) return 0;
  return bn_t::from_bin(out);
}

template<class ECURVE>
static error_t reconstruct_private_share(const ECURVE& ecurve, const crypto::rsa_key_t& prv_key, const typename ECURVE::point_t& Q_share, const backup_proofs_t& backup_proofs, bn_t& x_share)
{
  error_t rv = 0;

  bn_t q = ecurve.order();
  typename ECURVE::generator_t G = ecurve.generator();

  for (int j=0; j<security_param; j++)
  {
    bool ej = get_bit(backup_proofs.proof_e, j);
    bn_t r, y, x;
    if (!ej)
    {
      y = rsa_dec_oaep(prv_key, backup_proofs.proofs[j].c);
      if (y==0) return rv = ub::error(E_CRYPTO);
      x = (y - backup_proofs.proofs[j].ry) % q;
    }
    else 
    {
      r = rsa_dec_oaep(prv_key, backup_proofs.proofs[j].c);
      if (r==0) return rv = ub::error(E_CRYPTO);
      x = (backup_proofs.proofs[j].ry - r) % q;
    }

    if (G * x == Q_share)
    {
      x_share = x;
      return rv;
    }
  }
  return rv = ub::error(E_CRYPTO);
}

error_t reconstruct_private_share(const crypto::rsa_key_t& prv_key, const ecc_point_t& Q_share, const backup_proofs_t& backup_proofs, bn_t& x_share)
{
  ecurve_openssl_t ecurve(Q_share.get_curve());
  return reconstruct_private_share(ecurve, prv_key, Q_share, backup_proofs, x_share);
}


error_t reconstruct_private_key_from_shares(const crypto::rsa_key_t& prv_key, const backup_material_t& backup_material, bn_t& x)
{
  error_t rv = 0;
  int count = int(backup_material.v.size());
  if (count<1) return rv = ub::error(E_CRYPTO);
  bool is_eddsa = backup_material.v[0].eddsa;
  bn_t q;

  if (is_eddsa) q = crypto::ec25519::order();
  else
  {
    ecurve_t curve = backup_material.v[0].Q_share.get_curve();
    q = curve.order();
  }

  x = 0;
  bn_t x_share;
  for (int i=0; i<count; i++)
  {
    //if (rv = verify_backup_proofs(prv_key, share_materials[i])) return rv; // prv_key has also public key material
    if (is_eddsa)
    {
      if (rv = reconstruct_private_share_ed25519(prv_key, backup_material.v[i].Q_share_25519, backup_material.v[i].backup_proofs, x_share)) return rv;
    }
    else
    {
      if (rv = reconstruct_private_share(prv_key, backup_material.v[i].Q_share, backup_material.v[i].backup_proofs, x_share)) return rv;
    }
    MODULO (q) x += x_share;
  }
  return rv;
}


// Q_full is ECDSA public key
template <class ECURVE> static error_t verify_backup_material(const ECURVE& curve, const crypto::rsa_key_t& pub_key, const typename ECURVE::point_t& Q_full, const backup_material_t& backup_material)
{
  error_t rv = 0;
  int count = int(backup_material.v.size());
  if (count<1) return rv = ub::error(E_CRYPTO);


  typename ECURVE::point_t Q = curve.get_Q_share(backup_material.v[0]);

  for (int i=1; i<count; i++) 
  {
    Q += curve.get_Q_share(backup_material.v[i]);
  }
  if (Q!=Q_full) return rv = ub::error(E_CRYPTO);

  for (int i=0; i<count; i++)
  {
    if (rv = verify_backup_proofs(curve, pub_key, curve.get_Q_share(backup_material.v[i]), backup_material.v[i].backup_proofs)) return rv; 
  }

  return rv;
}

error_t verify_backup_material(const crypto::rsa_key_t& pub_key, const ecc_point_t& Q_full, const backup_material_t& backup_material)
{
  ecurve_openssl_t ecurve(Q_full.get_curve());
  return verify_backup_material(ecurve, pub_key, Q_full, backup_material);
}

error_t verify_backup_material_ed25519(const crypto::rsa_key_t& pub_key, const crypto::ecp_25519_t& Q_full, const backup_material_t& backup_material)
{
  ecurve_25519_t ecurve;
  return verify_backup_material(ecurve, pub_key, Q_full, backup_material);
}

static void convert_fixed_ec_point(ub::converter_t& converter, ecurve_t curve, ecc_point_t& point)
{
  int size = curve.get_compressed_oct_point_size();

  if (converter.is_write()) 
  {
    if (!converter.is_calc_size()) 
    {
      assert(point.get_curve()==curve);
      point.to_compressed_oct(converter.current());
    }
  }
  else
  {
    if (converter.is_error() || !converter.at_least(size)) { converter.set_error(); return; }
    point = ecc_point_t::from_oct(curve, mem_t(converter.current(), size));
    if (!curve.check(point)) { converter.set_error(); return; }
  }
  converter.forward(size);
}

static void convert_fixed_buf(ub::converter_t& converter, int size, buf_t& buf)
{
  if (converter.is_write()) 
  {
    if (!converter.is_calc_size()) 
    {
      assert(buf.size()==size);
      memmove(converter.current(), buf.data(), size);
    }
  }
  else
  {
    if (converter.is_error() || !converter.at_least(size)) { converter.set_error(); return; }
    buf = mem_t(converter.current(), size);
  }
  converter.forward(size);
}

static void convert_fixed_bn(ub::converter_t& converter, int size, bn_t& bn)
{
  if (converter.is_write()) 
  {
    if (!converter.is_calc_size()) 
    {
      assert(bn.get_bin_size()<=size);
      bn.to_bin(converter.current(), size);
    }
  }
  else
  {
    if (converter.is_error() || !converter.at_least(size)) { converter.set_error(); return; }
    bn = bn_t::from_bin(mem_t(converter.current(), size));
  }
  converter.forward(size);
}

int backup_material_t::get_converted_size(int parties_count, int rsa_key_size, ecurve_t curve)
{
  int curve_oct_size = curve.get_compressed_oct_point_size();
  int proof_size = curve.size() + rsa_key_size + 32;
  return 18 + parties_count * (curve_oct_size + security_param * proof_size + 16);
}

int backup_material_t::get_converted_size_ed25519(int parties_count, int rsa_key_size)
{
  int curve_bin_size = 32;
  int proof_size = 32 + rsa_key_size + 32;
  return 18 + parties_count * (curve_bin_size + security_param * proof_size + 16);
}



void backup_material_t::convert(ub::converter_t& converter)
{
  short count = (short)v.size();
  
  short security_param_count = 0;
  short curve_bits = 0;
  short curve_type = 0;
  ecurve_t curve = nullptr;
  bool is_eddsa = false;

  if (converter.is_write() && count)
  {
    security_param_count = (short)v[0].backup_proofs.proofs.size();
    is_eddsa = v[0].eddsa;
    if (is_eddsa)
    {
      curve_type = NID_ED25519;
      curve_bits = 256;
    }
    else
    {
      curve = v[0].Q_share.get_curve();
      curve_type = curve.get_openssl_code();
      curve_bits = curve.bits();
    }
  }

  converter.convert_code_type(0x65636261636B3031);
  converter.convert(security_param_count);
  converter.convert(curve_type);
  converter.convert(curve_bits);
  converter.convert(rsa_bits);
  converter.convert(count);
  
  if (!converter.is_write()) 
  {
    if (count>0)
    {
      if (security_param_count!=security_param) { converter.set_error(); return; }
      if ((rsa_bits<2048) || (rsa_bits % 8)) { converter.set_error(); return; }

      if (curve_type==NID_ED25519)
      {
        if (curve_bits!=256) { converter.set_error(); return; }
        is_eddsa = true;
      }
      else
      {
        curve = ecurve_t::find(curve_type);
        if (!curve) { converter.set_error(); return; }
        if (curve.bits()!=curve_bits) { converter.set_error(); return; }
      }
    }
    v.resize(count);
  }

  for (int i=0; i<count; i++)
  {
    party_backup_material_t& mat = v[i];

    if (is_eddsa) 
    {
      mat.eddsa = is_eddsa;
      converter.convert(mat.Q_share_25519);
    }
    else convert_fixed_ec_point(converter, curve, mat.Q_share);

    backup_proofs_t& proofs = mat.backup_proofs;

    if (!converter.is_write()) proofs.proofs.resize(security_param_count);

    for (int j=0; j<security_param_count; j++)
    {
      proof_z_t& z = proofs.proofs[j];

      convert_fixed_bn(converter, curve_bits/8, z.ry);
      convert_fixed_bn(converter, rsa_bits/8, z.c);
      convert_fixed_buf(converter, 32, z.s);
    }

    // prof_e
    convert_fixed_buf(converter, 16, proofs.proof_e);
  }
}


error_t generate_backup_proofs_ed25519(const crypto::rsa_key_t& pub_key, const bn_t& x_share, backup_proofs_t& backup_proofs)
{
  ecurve_25519_t ecurve;
  return generate_backup_proofs(ecurve, pub_key, x_share, backup_proofs);
}

error_t verify_backup_proofs_ed25519(const crypto::rsa_key_t& pub_key, const crypto::ecp_25519_t& Q_share, const backup_proofs_t& backup_proofs)
{
  ecurve_25519_t ecurve;
  return verify_backup_proofs(ecurve, pub_key, Q_share, backup_proofs);
}

error_t reconstruct_private_share_ed25519(const crypto::rsa_key_t& prv_key,  const crypto::ecp_25519_t& Q_share, const backup_proofs_t& backup_proofs, bn_t& x_share)
{
  ecurve_25519_t ecurve;
  return reconstruct_private_share(ecurve, prv_key, Q_share, backup_proofs, x_share);
}

}
