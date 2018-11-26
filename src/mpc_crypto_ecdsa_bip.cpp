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
#include "mpc_crypto_ecdsa_bip.h"
#include "crypto_ecc_bip.h"
#include "circuit_data.h"


// --------------------------------- gcdef_bip_t ---------------------------------------


circuit_def_t::wires_t gcdef_bip_t::bn_to_wires(const bn_t& value, int bits)
{
  buf_t buf = value.to_bin(bits/8);
  buf.reverse();
  wires_t out(bits);
  for (int i=0; i<bits; i++) 
  {
    bool bit = get_bit(buf.data(), i);
    out[i] = bit ? gc_true : gc_false; //get_const_wire();
  }
  return out;
}

void gcdef_bip_t::set_const_4(wires_t& dst, int offset, unsigned value)
{
  byte_t buffer[4];
  ub::be_set_4(buffer, value);
  for (int i=0; i<32; i++) dst[offset+i] = get_const_wire(get_bit(buffer, i));
}

void gcdef_bip_t::set_const_8(wires_t& dst, int offset, uint64_t value)
{
  byte_t buffer[8];
  ub::be_set_8(buffer, value);
  for (int i=0; i<64; i++) dst[offset+i] = get_const_wire(get_bit(buffer, i));
}

circuit_def_t::wires_t gcdef_bip_t::hmac(wires_t& opad_state, wires_t& ipad_state, wires_t& in)
{
  int data_size = (int)in.size()/8;
  const int block_size = 128;
  const int state_size = 64;
  opad_state.init(state_size*8);
  ipad_state.init(state_size*8);
  wires_t out(state_size*8);

  wires_t in_state;
  wires_t out_state(state_size*8);

  int block_count = ((data_size + 9) + block_size - 1) / block_size;
 
  wires_t hmac_input(block_count*block_size*8);
  for (int i=0; i<data_size*8; i++) hmac_input[i] = in[i];

  for (int i=data_size*8; i<block_count*block_size*8; i++) hmac_input[i] = get_wire_false();
  hmac_input[data_size*8+7] = get_wire_true();

  set_const_8(hmac_input, block_count*block_size*8-64, (block_size+data_size)*8);

  for (int i=0; i<block_count; i++)
  {
    wires_t block(block_size*8);
    for (int j=0; j<block_size*8; j++) block[j] = hmac_input[i*block_size*8+j];
    load_compressed(get_sha512_update_bin(), out_state, block, i==0 ? ipad_state : in_state);
    in_state = out_state;
  }

  wires_t block(block_size*8);
  for (int i=0; i<state_size*8; i++) block[i] = out_state[i];
  for (int i=state_size*8; i<block_size*8; i++) block[i] = get_wire_false();
  block[state_size*8+7] = get_wire_true();

  set_const_8(block, block_size*8-64, (block_size+state_size)*8);

  load_compressed(get_sha512_update_bin(), out, block, opad_state);    
  return out;
}

circuit_def_t::wires_t gcdef_bip_t::pad(wires_t& a)
{
  update_wires(a);

  int size = (int)a.size();
  wires_t b(size+1);
  for (int i=0; i<size; i++) b[i] = a[i];
  b[size] = get_wire_false();
  return b;
}

int gcdef_bip_t::gt(wires_t& a, wires_t& b)
{
  return build_gt(a, b);
}

circuit_def_t::wires_t gcdef_bip_t::add(wires_t& a, wires_t& b)
{
  wires_t a_pad = pad(a);
  wires_t b_pad = pad(b); 
  wires_t c((int)a_pad.size()); 
  build_add(&c, a_pad, b_pad, nullptr, nullptr);
  return c;
}

circuit_def_t::wires_t gcdef_bip_t::sub(wires_t& a, wires_t& b)
{
  wires_t c((int)a.size()); 
  build_sub(c, a, b);
  return c;
}

circuit_def_t::wires_t gcdef_bip_t::add_mod(wires_t& a, wires_t& b, wires_t& m)
{ 
  wires_t a_plus_b = add(a, b); 
  wires_t m_pad = pad(m);
  wires_t a_plus_b_minus_m = sub(a_plus_b, m_pad);
  
  int normal = gt(m_pad, a_plus_b);
  int overflow = not_gate(normal);

  int size = int(m.size());
  wires_t c(size);
  for (int i=0; i<size; i++)
  {
    int case_normal = and_gate(normal, a_plus_b[i]);
    int case_overflow = and_gate(overflow, a_plus_b_minus_m[i]);
    c[i] = or_gate(case_overflow, case_normal);
  }
  return c;
}

circuit_def_t::wires_t gcdef_bip_t::xor_gates(wires_t& in1, wires_t& in2)
{
  circuit_def_t::wires_t dst((int)in1.size());
  circuit_def_t::xor_gates(dst, in1, in2);
  return dst;
}


circuit_def_t::wires_t gcdef_bip_t::sub_mod(wires_t& a, wires_t& b, wires_t& m)
{
  int l_size = (int)m.size();

  int normal = gt(a, b);
  int underflow = not_gate(normal);

  wires_t a_minus_b = sub(a, b);
  wires_t a_plus_m = add(a, m);
  
  wires_t b_pad = pad(b);
  wires_t a_plus_m_minus_b = sub(a_plus_m, b_pad);
  
  int size = int(m.size());
  wires_t c(size);
  for (int i=0; i<size; i++)
  {
    int case_normal = and_gate(normal, a_minus_b[i]);
    int case_underflow = and_gate(underflow, a_plus_m_minus_b[i]);
    c[i] = or_gate(case_normal, case_underflow);
  }
  return c;
}

gcdef_bip_t::gcdef_bip_t(int initial_seed_size, unsigned index)
{
  wires_t opad_state, ipad_state, in1, in2, hmac_in;

  const int q_size = 256;

  wires_t prev_x(q_size);
  wires_t x(q_size);

  bool initial = initial_seed_size >= 0;

  int in_size = initial ? initial_seed_size*8 : q_size;
  in1.init(in_size); update_wires(in1);
  in2.init(in_size); update_wires(in2);
  

  wires_t q(q_size);

  if (initial)
  {
    hmac_in = xor_gates(in1, in2);
  }
  else
  {
    hmac_in.init(8+q_size+32);

    for (int i=0; i<8; i++) hmac_in[i] = get_wire_false(); // first zero byte

    prev_x = add_mod(in1, in2, q);
    wires_t prev_x_swap = prev_x; prev_x_swap.swap_bytes();
    for (int i=0; i<q_size; i++) hmac_in[8+i] = prev_x_swap[i];

    set_const_4(hmac_in, 8+q_size, index);
  }

  wires_t hmac_out = hmac(opad_state, ipad_state, hmac_in);

  wires_t out_c_par(q_size);
  for (int i=0; i<q_size; i++) out_c_par[i] = hmac_out[q_size+i];

  if (initial)
  {
    for (int i=0; i<q_size; i++) x[i] = hmac_out[i];
    x.swap_bytes();
  }
  else
  {
    wires_t delta(q_size);
    for (int i=0; i<q_size; i++) delta[i] = hmac_out[i];
    delta.swap_bytes();
    x = add_mod(prev_x, delta, q);
  }

  wires_t alpha1(128);
  wires_t alpha2(128);
  wires_t alpha = xor_gates(alpha1, alpha2);

  wires_t rhos[64];
  wires_t out_x1[64];
  wires_t out_x2[64];

  for (int i=0; i<64; i++)
  {
    rhos[i].init(q_size); update_wires(rhos[i]);

    wires_t rho = rhos[i];
    rho.resize(q_size);

    out_x1[i] = rho;
    out_x2[i].init(q_size);
    wires_t w0, w1, w2;

    w0 = rho;
    w2 = sub_mod(x, rho, q);

    if (initial)
    {
      w1 = sub(q, rho);
    }
    else
    {
      w1 = sub_mod(prev_x, rho, q);
    }

    int alpha_i = alpha[i*2];
    int alpha_i_plus_1 = alpha[i*2+1];
    int not_alpha_i_plus_1 =  not_gate(alpha_i_plus_1);
    int case0 = not_gate(alpha_i);
    int case1 = and_gate(alpha_i, not_alpha_i_plus_1);
    int case2 = and_gate(alpha_i, alpha_i_plus_1);

    for (int j=0; j<q_size; j++)
    {
      if (i==0)
      {
        out_x2[i][j] = w2[j];
      }
      else
      {
        int out0 = and_gate(case0,  w0[j]);
        int out1 = and_gate(case1,  w1[j]);
        int out2 = and_gate(case2,  w2[j]);

        int out_temp = or_gate(out0, out1);
        out_x2[i][j] = or_gate(out2, out_temp);
      }
    }
  }

  q_param = set_input_param(q);

  opad_param = set_input_param(opad_state);
  ipad_param = set_input_param(ipad_state);
  in1_param = set_input_param(in1);
  in2_param = set_input_param(in2);
  out_c_par_param = set_output_param(out_c_par);
  alpha1_param = set_input_param(alpha1);
  alpha2_param = set_input_param(alpha2);

  for (int i=0; i<64; i++)
  {
    rho_param[i] = set_input_param(rhos[i]);
    out_x1_param[i] = set_output_param(out_x1[i]);
    out_x2_param[i] = set_output_param(out_x2[i]);
  }
}

class cache_gcdef_bip_t
{
public:
  static const gcdef_bip_t* get(int initial_seed_size, unsigned index);

private:
  unordered_map_t<uint64_t, const gcdef_bip_t*> map;
  ub::mutex_t lock;
};
static ub::global_t<cache_gcdef_bip_t> g_cache_gcdef_bip;
const gcdef_bip_t* cache_gcdef_bip_t::get(int initial_seed_size, unsigned index)
{
  uint64_t key = (uint64_t(index)<<32) | uint32_t(initial_seed_size);

  cache_gcdef_bip_t& cache = g_cache_gcdef_bip.instance();
  ub::scoped_lock_t scoped(cache.lock);
  const auto& i = cache.map.find(key);
  if (i!=cache.map.end()) return i->second;

  const gcdef_bip_t* gcdef = new gcdef_bip_t(initial_seed_size, index);
  cache.map[key] = gcdef;
  return gcdef;
}


//-------------------------------------------------------------------------------------

enum { max_ot_blocks = 150 };

void mpc_ecdsa_derive_bip_t::convert(ub::converter_t& converter) 
{
  converter.convert_code_type(CODE_TYPE);

  converter.convert(hardened);
  converter.convert(initial);
  converter.convert(child_index);
  converter.convert(old_seed_share);
  converter.convert(old_ecdsa_share);
  converter.convert(old_bip_level);
  converter.convert(old_c_par);
  converter.convert(new_share);
  converter.convert(new_parent_fingerprint);
  converter.convert(new_c_par);
  converter.convert(ot_base_init_sender);
  converter.convert(ot_base_init_receiver);
  converter.convert(ot_sender);
  converter.convert(ot_receiver);
  converter.convert(gc_initialized);
  converter.convert(session_id);

  if (gc_initialized)
  {
    init_circuit_def();
    gc.def = mpc_circuit_def;
    gc.ot_sender = &ot_sender;
    gc.ot_receiver = &ot_receiver;    

    converter.convert(gc);
    converter.convert(rho);
    converter.convert(alpha1);
    converter.convert(alpha2);

    converter.convert(new_x);
    converter.convert(Q1);
    converter.convert(Q2);
    converter.convert(comm_Q2_rand);
    converter.convert(comm_Q2_hash);
    converter.convert(gen_helper);
    converter.convert(agree_random);
  }

  mpc_crypto_context_t::convert(converter);
}

int mpc_ecdsa_derive_bip_t::get_messages_count() const
{
  if (initial) return 9;
  if (hardened) return 9;
  return 0;
}

error_t mpc_ecdsa_derive_bip_t::party1_step1(none_message_t& out)
{
  return 0;
}

void mpc_ecdsa_derive_bip_t::get_share_core(mpc_crypto_share_t& dst) const
{
  assert(false);
}

void mpc_ecdsa_derive_bip_t::set_share_core(const mpc_crypto_share_t& src)
{
  assert(false);
}


error_t mpc_ecdsa_derive_bip_t::init(bool hardened, unsigned index, const mpc_ecdsa_share_t& ecdsa_share)
{
  error_t rv = 0;
  this->initial = false;
  this->hardened = hardened;
  this->child_index = index;
  this->old_ecdsa_share = ecdsa_share.core;
  this->old_bip_level = ecdsa_share.bip.level;
  this->old_c_par = ecdsa_share.bip.c_par;

  if (!hardened)
  {
    if (rv = execute_normal_derivation()) return rv;
  }

  buf_t ripemd_hash = crypto::ripemd160_t::hash(sha256_t::hash(old_ecdsa_share.Q_full.to_compressed_oct()));
  new_parent_fingerprint = ub::be_get_4(ripemd_hash.data());

  return rv;
}

error_t mpc_ecdsa_derive_bip_t::init(const mpc_generic_secret_share_t& seed_share)
{
  error_t rv = 0;
  this->initial = true;
  this->hardened = false;
  this->child_index = 0;
  this->old_seed_share = seed_share.value;
  this->new_parent_fingerprint = 0;
  return rv;
}

error_t mpc_ecdsa_derive_bip_t::get_result_share(mpc_crypto_share_t*& result_share) const
{
  error_t rv = 0;
  mpc_ecdsa_share_t* new_ecdsa_share = new mpc_ecdsa_share_t;
  new_ecdsa_share->core = new_share;
  new_ecdsa_share->set_uid(new_ecdsa_share->calc_uid());
  new_ecdsa_share->bip.hardened = hardened;
  new_ecdsa_share->bip.level = initial ? 0 : old_bip_level+1;
  new_ecdsa_share->bip.child_number = child_index;
  new_ecdsa_share->bip.parent_fingerprint = new_parent_fingerprint;
  new_ecdsa_share->bip.c_par = new_c_par;

  result_share = new_ecdsa_share;
  return rv;
}

error_t mpc_ecdsa_derive_bip_t::execute_normal_derivation()
{
  error_t rv = 0;

  ecurve_t curve = crypto::curve_k256;
  const ecc_generator_point_t& G = curve.generator();
  const bn_t& q = curve.order();

  buf256_t c_par = old_c_par;
  ecc_point_t src_Q = old_ecdsa_share.Q_full;
  buf_t I = crypto::hmac_sha512_t(c_par).calculate(src_Q, child_index);
  new_c_par = buf256_t::load(I.data()+32);

  bn_t delta = bn_t::from_bin(mem_t(I.data(), 32));
  new_share.Q_full = src_Q + G * delta;
  new_share.paillier = old_ecdsa_share.paillier;

  if (peer==1)
  {
    bn_t x1 = old_ecdsa_share.x;
    new_share.x = (x1 + delta) % q;
    new_share.c_key = 0;
  }
  else // peer==2
  {
    bn_t c_key_2 = old_ecdsa_share.c_key;
    new_share.c_key = old_ecdsa_share.paillier.add_scalar(c_key_2, delta); 
    new_share.x = old_ecdsa_share.x;
  }

  return rv;
}


error_t mpc_ecdsa_derive_bip_t::party1_step1(message1_t& out) // step 1
{
  ot_base_init_receiver.rec_step1(ot_receiver, out.ot_base_init1_msg1); //ot_base_init1
  return 0;
}

error_t mpc_ecdsa_derive_bip_t::party2_step1(const message1_t& in, message2_t& out)  // step 2
{
  error_t rv = 0;
  if (rv = ot_base_init_sender.snd_step2(ot_sender, in.ot_base_init1_msg1, out.ot_base_init1_msg2)) return rv; //ot_base_init1
  ot_base_init_receiver.rec_step1(ot_receiver, out.ot_base_init2_msg1); //ot_base_init2
  return 0;
}

static buf_t get_q_buf_le()
{
  ecurve_t curve = crypto::curve_k256;
  const bn_t& q = curve.order();
  buf_t buf = q.to_bin(32); buf.reverse();
  return buf;
}

static const char bitcoin_seed[] = "Bitcoin seed";

static void set_hmac_pad(int param_index, gc_plain_t& input, mem_t key, byte_t pad_byte)
{
  const int block_size = 128;
  const int state_size = 64;

  byte_t pad_data[block_size]; 
  for (int i=0; i<block_size; i++) pad_data[i] = pad_byte; 
  for (int i=0; i<key.size; i++) pad_data[i]^=key[i];

  byte_t state[state_size];

  crypto::hash_state_t hash_state(crypto::hash_e::sha512);
  hash_state.update(mem_t(pad_data, block_size));
  hash_state.get_state(state);

  input.set_param(param_index, mem_t(state, state_size));
}

static void set_hmac_key(const gcdef_bip_t* circuit_def, gc_plain_t& input, mem_t key)
{
  set_hmac_pad(circuit_def->ipad_param, input, key, 0x36);
  set_hmac_pad(circuit_def->opad_param, input, key, 0x5c);
}

static void set_initial_hmac_key(const gcdef_bip_t* circuit_def, gc_plain_t& input)
{
  set_hmac_key(circuit_def, input, mem_t(const_byte_ptr(bitcoin_seed), sizeof(bitcoin_seed)-1));
}

static void set_rho(const gcdef_bip_t* circuit_def, gc_plain_t& input, const std::vector<bn_t>& rho)
{
  for (int i=0; i<64; i++)
  {
    buf_t rho_data = rho[i].to_bin(32); rho_data.reverse();
    int param = circuit_def->rho_param[i];
    input.set_param(param, rho_data);
  } 
}


void mpc_ecdsa_derive_bip_t::init_circuit_def()
{
  unsigned child_index_fix = child_index;
  if (hardened) child_index_fix |= 0x80000000;

  if (!circuit_def) circuit_def = cache_gcdef_bip_t::get(initial ? old_seed_share.size() : -1, initial ? 0 : child_index_fix);
  if (!mpc_circuit_def) 
  {
    mpc_circuit_def = new mpc_circuit_def_t(*circuit_def);
    mpc_circuit_def->set_input_param(circuit_def->q_param, gc_param_type_e::party12);  
    mpc_circuit_def->set_input_param(circuit_def->opad_param, gc_param_type_e::party12);  
    mpc_circuit_def->set_input_param(circuit_def->ipad_param, gc_param_type_e::party12);  
    mpc_circuit_def->set_input_param(circuit_def->in1_param, gc_param_type_e::party1);
    mpc_circuit_def->set_input_param(circuit_def->in2_param, gc_param_type_e::party2);
    mpc_circuit_def->set_output_param(circuit_def->out_c_par_param, gc_param_type_e::party12);  
    mpc_circuit_def->set_input_param(circuit_def->alpha1_param, gc_param_type_e::party1);
    mpc_circuit_def->set_input_param(circuit_def->alpha2_param, gc_param_type_e::party2);

    for (int i=0; i<64; i++)
    {
      mpc_circuit_def->set_input_param(circuit_def->rho_param[i], gc_param_type_e::party1);
      mpc_circuit_def->set_output_param(circuit_def->out_x1_param[i], gc_param_type_e::party1);
      mpc_circuit_def->set_output_param(circuit_def->out_x2_param[i], gc_param_type_e::party2);
    }

    gc.def = mpc_circuit_def;
  }
}

void mpc_ecdsa_derive_bip_t::gc_init_peer1()
{
  init_circuit_def();
  gc_plain_t input1(mpc_circuit_def->get_input_params(gc_param_type_e::party1) | mpc_circuit_def->get_input_params(gc_param_type_e::party12));
  input1.set_param(circuit_def->q_param, get_q_buf_le());
  
  ecurve_t curve = crypto::curve_k256;
  const bn_t& q = curve.order();
  alpha1 = buf128_t::rand();
  rho.resize(64);
  for (int i=0; i<64; i++) rho[i] = bn_t::rand(q);

  if (initial)
  {
    set_initial_hmac_key(circuit_def, input1);
    input1.set_param(circuit_def->in1_param, old_seed_share);
  }
  else
  {
    set_hmac_key(circuit_def, input1, mem_t(old_c_par));
    buf_t prev_x = old_ecdsa_share.x.to_bin(32); prev_x.reverse();
    input1.set_param(circuit_def->in1_param, prev_x);
  }

  input1.set_param(circuit_def->alpha1_param, mem_t(alpha1));
  set_rho(circuit_def, input1, rho);

  gc.init(true, mpc_circuit_def, &ot_sender, &ot_receiver, input1);
  gc_initialized = true;
}

void mpc_ecdsa_derive_bip_t::gc_init_peer2()
{

  init_circuit_def();

  gc_plain_t input2(mpc_circuit_def->get_input_params(gc_param_type_e::party2) | mpc_circuit_def->get_input_params(gc_param_type_e::party12));
  input2.set_param(circuit_def->q_param, get_q_buf_le());

  ecurve_t curve = crypto::curve_k256;
  const bn_t& q = curve.order();
  alpha2 = buf128_t::rand();

  if (initial)
  {
    set_initial_hmac_key(circuit_def, input2);
    input2.set_param(circuit_def->in2_param, old_seed_share);
  }
  else
  {
    set_hmac_key(circuit_def, input2, mem_t(old_c_par));
    buf_t prev_x = old_ecdsa_share.x.to_bin(32); prev_x.reverse();
    input2.set_param(circuit_def->in2_param, prev_x);
  }
  input2.set_param(circuit_def->alpha2_param, mem_t(alpha1));

  gc.init(false, mpc_circuit_def, &ot_sender, &ot_receiver, input2);
  gc_initialized = true;
}


error_t mpc_ecdsa_derive_bip_t::party1_step2(const message2_t& in, message3_t& out) // step 3
{
  error_t rv = 0;
  ot_base_init_receiver.rec_step3(ot_receiver, in.ot_base_init1_msg2); //ot_base_init1
  if (rv = ot_base_init_sender.snd_step2(ot_sender, in.ot_base_init2_msg1, out.ot_base_init2_msg2)) return rv; //ot_base_init2
  ot_extend_receiver.rec_step1(max_ot_blocks, ot_receiver, out.ot_extend1_msg1); //ot_extend1

  gc_init_peer1();
  if (rv = gc.peer1_step1(out.gc_msg1)) return rv;

  return 0;
}

error_t mpc_ecdsa_derive_bip_t::party2_step2(const message3_t& in, message4_t& out) // step 4
{
  error_t rv = 0;

  ot_base_init_receiver.rec_step3(ot_receiver, in.ot_base_init2_msg2); //ot_base_init2
  if (rv = ot_extend_sender.snd_step2(max_ot_blocks, ot_sender, in.ot_extend1_msg1)) return rv; //ot_extend1
  
  ot_extend_receiver.rec_step1(max_ot_blocks, ot_receiver, out.ot_extend2_msg1);  //ot_extend2
  gc_init_peer2();
  if (rv = gc.peer2_step2(in.gc_msg1, out.gc_msg2))  return rv; 
  
  agree_random.peer1_step1(out.agree_msg1);
  return 0;
}

error_t mpc_ecdsa_derive_bip_t::party1_step3(const message4_t& in, message5_t& out) // step 5
{
  error_t rv = 0;

  if (rv = ot_extend_sender.snd_step2(max_ot_blocks, ot_sender, in.ot_extend2_msg1)) return rv;  //ot_extend2
  if (rv = gc.peer1_step3(in.gc_msg2, out.gc_msg3))  return rv; 
  if (rv = agree_random.peer2_step1(in.agree_msg1, out.agree_msg2)) return rv;

  return 0;
}

static std::vector<bn_t> get_out_x(const int* param_tab, const gc_plain_t& output) 
{
  std::vector<bn_t> out_x(64); 

  buf_t x_data;
  for (int i=0; i<64; i++)
  {
    x_data = output.get_param(param_tab[i]); x_data.reverse(); 
    out_x[i] = bn_t::from_bin(x_data);    
  }

  return out_x;
}

error_t mpc_ecdsa_derive_bip_t::party2_step3(const message5_t& in, message6_t& out) // step 6
{
  error_t rv = 0;
  if (rv = agree_random.peer1_step2(in.agree_msg2, out.agree_msg3, session_id)) return rv; 
  if (rv = gc.peer2_step4(in.gc_msg3, out.gc_msg4)) return rv;


  buf_t new_c_par_buf = gc.unverified_output.get_param(circuit_def->out_c_par_param);
  new_c_par = buf256_t::load(new_c_par_buf.data());
  new_x = get_out_x(circuit_def->out_x2_param, gc.unverified_output);

  ecurve_t curve = crypto::curve_k256;
  const ecc_generator_point_t& G = curve.generator();
  
  Q2.resize(64);
  sha256_t sha256;
  for (int i=0; i<64; i++) 
  {
    Q2[i] = G * new_x[i];
    sha256.update(Q2[i]);
  }
  
  mpc::commitment_t comm_Q2;
  comm_Q2.gen(sha256);
  comm_Q2_hash = out.comm_Q2_hash = comm_Q2.hash;
  comm_Q2_rand = comm_Q2.rand;

  out.Q2_first = Q2[0];

  return 0;
}

error_t mpc_ecdsa_derive_bip_t::check_new_Q()
{
  error_t rv = 0;
  /*
  Q_index = -1;

  ecc_point_t Q;
  ecc_point_t src_Q;
  if (!initial) src_Q = old_ecdsa_share.Q_full;

  for (int i=0; i<64; i++) 
  {
    if (Q1[i]==Q2[i]) continue;

    ecc_point_t Q_i = Q1[i] + Q2[i];

    if (initial)
    {
      if (Q_i.is_infinity()) continue;
    }
    else
    {
      if (Q_i == src_Q) continue;
    }

    if (Q_index>=0)
    {
      if (Q_i!=Q) return rv = ub::error(E_CRYPTO);
    }
    else 
    { 
      Q = Q_i; 
      Q_index = i; 
    }
  }

  if (Q_index<0) return rv = ub::error(E_CRYPTO);
  new_share.Q_full = Q;
  */
  return rv;
}

error_t mpc_ecdsa_derive_bip_t::party1_step4 (const message6_t& in,  message7_t& out) // step 7
{
  error_t rv = 0;
  if (rv = agree_random.peer2_step2(in.agree_msg3, session_id)) return rv;
  if (rv = gc.peer1_step5(in.gc_msg4, out.gc_msg5))  return rv; 

  buf_t new_c_par_buf = gc.unverified_output.get_param(circuit_def->out_c_par_param);
  new_c_par = buf256_t::load(new_c_par_buf.data());
  new_x = get_out_x(circuit_def->out_x1_param, gc.unverified_output);

  ecurve_t curve = crypto::curve_k256;
  const ecc_generator_point_t& G = curve.generator();

  Q1.resize(64);

  sha256_t sha256;
  for (int i=0; i<64; i++) 
  {
    Q1[i] = G * new_x[i];
    sha256.update(Q1[i]);
  }

  int Q_index = 0;
  new_share.x = new_x[Q_index];
  new_share.Q_full = in.Q2_first + Q1[0];

  gen_helper.peer1_step1(true, curve, session_id, new_share, out.gen_msg1);

  comm_Q2_hash = in.comm_Q2_hash;
  out.Q1 = Q1;
  return 0;
}

error_t mpc_ecdsa_derive_bip_t::party2_step4(const message7_t& in,  message8_t& out) // step 8
{
  error_t rv = 0;

  ecurve_t curve = crypto::curve_k256;
  Q1 = in.Q1;
  if (Q1.size()!=64) return rv = ub::error(E_CRYPTO);
  for (int i=0; i<64; i++) 
  {
    if (!curve.check(Q1[i])) return rv = ub::error(E_CRYPTO);
  } 

  if (rv = check_new_Q()) return rv;
  new_share.x = new_x[0];
  new_share.Q_full = Q1[0] + Q2[0];

  if (rv = gen_helper.peer2_step1(true, curve, session_id, new_share, in.gen_msg1, out.gen_msg2)) return rv;

  out.comm_Q2_rand = comm_Q2_rand;
  out.Q2 = Q2;
  return 0;
}


error_t mpc_ecdsa_derive_bip_t::party1_step5(const message8_t& in, message9_t& out)  // step 9 
{
  error_t rv = 0;
  ecurve_t curve = crypto::curve_k256;

  Q2 = in.Q2;
  if (Q2.size()!=64) return rv = ub::error(E_CRYPTO);
  sha256_t sha256;
  for (int i=0; i<64; i++) 
  {
    if (!curve.check(Q2[i])) return rv = ub::error(E_CRYPTO);
    sha256.update(Q2[i]);
  } 

  if (rv = check_new_Q()) return rv;

  if (!mpc::commitment_t::check(in.comm_Q2_rand, comm_Q2_hash, sha256)) return rv = ub::error(E_CRYPTO); 

  return rv = gen_helper.peer1_step2(new_share, in.gen_msg2, out);
}

error_t mpc_ecdsa_derive_bip_t::party2_step5(const message9_t& in, none_message_t& out)  // step 10
{ 
  return gen_helper.peer2_step2(new_share, in);
}

MPCCRYPTO_API int MPCCrypto_initDeriveBIP32(int peer, MPCCryptoShare* share_ptr, int hardened, unsigned index, MPCCryptoContext** context)
{
  error_t rv = 0;

  if (!context) return rv = ub::error(E_BADARG);
  if (!share_ptr) return rv = ub::error(E_BADARG);
  if (index & 0x80000000) return rv = ub::error(E_BADARG);

  mpc_generic_secret_share_t* seed_share = nullptr;
  mpc_ecdsa_share_t* ecdsa_share = dynamic_cast<mpc_ecdsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!ecdsa_share) 
  {
    seed_share = dynamic_cast<mpc_generic_secret_share_t*>((mpc_crypto_share_t*)share_ptr);
    if (!seed_share) return rv = ub::error(E_BADARG);
  }

  mpc_ecdsa_derive_bip_t* derive = new mpc_ecdsa_derive_bip_t();
  derive->set_peer(peer);
  if (ecdsa_share)
  {
    derive->set_share_uid(ecdsa_share->get_uid());   
    if (rv = derive->init(hardened!=0, index, *ecdsa_share)) 
    {
      delete derive;
      return rv;
    }
  }
  else
  {
    if (hardened) return rv = ub::error(E_BADARG);
    if (index!=0) return rv = ub::error(E_BADARG);
    derive->set_share_uid(seed_share->get_uid());
    if (rv = derive->init(*seed_share)) 
    {
      delete derive;
      return rv;
    }
  }

  *context = (MPCCryptoContext*)derive;
  return rv;
}

MPCCRYPTO_API int MPCCrypto_getResultDeriveBIP32(MPCCryptoContext* context, MPCCryptoShare** new_share_ptr)
{
  error_t rv = 0;

  if (!context) return rv = ub::error(E_BADARG);
  mpc_ecdsa_derive_bip_t* derive = dynamic_cast<mpc_ecdsa_derive_bip_t*>((mpc_crypto_context_t*)context);
  if (!derive) return rv = ub::error(E_BADARG);

  mpc_crypto_share_t* new_share = nullptr;
  if (rv = derive->get_result_share(new_share)) return rv;
  *new_share_ptr = (MPCCryptoShare*)new_share;

  return 0;
}


MPCCRYPTO_API int MPCCrypto_getBIP32Info(MPCCryptoShare* share_ptr, bip32_info_t* bip_info)
{
  error_t rv = 0;
  if (!share_ptr) return rv = ub::error(E_BADARG);
  if (!bip_info) return rv = ub::error(E_BADARG);
  mpc_ecdsa_share_t* share = dynamic_cast<mpc_ecdsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!share) return rv = ub::error(E_BADARG);

  share->get_bip_info(*bip_info);

  return rv;
}

MPCCRYPTO_API int MPCCrypto_serializePubBIP32(MPCCryptoShare* share_ptr, char* out, int* out_size)
{
  error_t rv = 0;
  if (!share_ptr) return rv = ub::error(E_BADARG);
  if (!out_size) return rv = ub::error(E_BADARG);
  mpc_ecdsa_share_t* share = dynamic_cast<mpc_ecdsa_share_t*>((mpc_crypto_share_t*)share_ptr);
  if (!share) return rv = ub::error(E_BADARG);

  bip32_info_t bip_key_info;
  share->get_bip_info(bip_key_info);

  ecc_point_t Q = share->core.Q_full;

  if (bip_key_info.hardened) bip_key_info.child_number |= 0x80000000;

  crypto::bip_node_t bip_node;
  bip_node.set_child_number(bip_key_info.child_number);
  bip_node.set_c_par(buf256_t::load(bip_key_info.chain_code));
  bip_node.set_parent_fingerprint(bip_key_info.parent_fingerprint);
  bip_node.set_level(bip_key_info.level);

  std::string s = bip_node.serialize_pub(Q.to_compressed_oct());
  int len = (int)s.length()+1;
  int buf_size = *out_size;
  *out_size = len;
  
  if (out)
  {
    if (buf_size < len) return ub::error(E_TOO_SMALL);
    memmove(out, s.c_str(), len);
  }

  return rv;
}
