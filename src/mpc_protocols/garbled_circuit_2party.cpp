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
#include "garbled_circuit_2party.h"


static bool get_label_lsb(buf128_t v)
{
  return 0 != (int(v.le_half0()) & 1);
}


// ----------------------------- gc_params_t -----------------
gc_params_t::gc_params_t(const std::vector<circuit_def_t::wires_t>& wires)
{
  list.resize(wires.size());
  int index = 0;
  FOR_EACH(i, wires) list[index++] = (int)i->size();
}

int gc_params_t::get_count() const
{
  int count = 0;
  FOR_EACH(i, list) if (*i) count++;
  return count;
}


void gc_params_t::set(int param_index, int param_bits)
{
  assert(param_bits);
  if (param_index>=(int)list.size()) list.resize(param_index+1, 0);
  list[param_index] = param_bits;
}

int gc_params_t::get_bits_count() const
{
  int bits = 0;
  FOR_EACH(i, list) bits += *i;
  return bits;
}

gc_params_t operator | (const gc_params_t& p1, const gc_params_t& p2)
{
  gc_params_t result = p1;
  
  int index2 = 0;
  FOR_EACH(s2, p2.list) 
  {
    if (*s2) result.set(index2, *s2);
    index2++;
  }
  return result;
}

gc_params_t operator & (const gc_params_t& p1, const gc_params_t& p2)
{
  int len = (int)std::min(p1.list.size(), p2.list.size());
  gc_params_t result;

  for (int i=0; i<len; i++)
  {
    int bits1 = p1.list[i];
    int bits2 = p2.list[i];
    if (!bits1 || !bits2) continue;
    assert(bits1==bits2);
    result.set(i, bits1);
  }

  return result;
}

gc_params_t operator - (const gc_params_t& p1, const gc_params_t& p2)
{
  int len = (int)std::min(p1.list.size(), p2.list.size());
  gc_params_t result;

  for (int i=0; i<len; i++)
  {
    int bits1 = p1.list[i];
    int bits2 = p2.list[i];
    if (!bits1 || bits2) continue;
    result.set(i, bits1);
  }

  return result;
}

// ----------------------- mpc_circuit_def_t -----------------

void mpc_circuit_def_t::set_input_param(int param_index, gc_param_type_e type)
{
  tab_input[int(type)].insert(param_index);
}

void mpc_circuit_def_t::set_output_param(int param_index, gc_param_type_e type)
{
  tab_output[int(type)].insert(param_index);
}


gc_params_t mpc_circuit_def_t::get_input_param(int param_index) const
{
  return gc_params_t(param_index, def.get_input_param_bits_count(param_index));
}

gc_params_t mpc_circuit_def_t::get_output_param(int param_index) const
{
  return gc_params_t(param_index, def.get_output_param_bits_count(param_index));
}

gc_params_t mpc_circuit_def_t::get_input_params(gc_param_type_e type) const
{
  const auto& set = tab_input[int(type)];

  gc_params_t result;
  FOR_EACH(i, set) result.set(*i, def.get_input_param_bits_count(*i));
  return result;
}

gc_params_t mpc_circuit_def_t::get_output_params(gc_param_type_e type) const
{
  const auto& set = tab_output[int(type)];

  gc_params_t result;
  FOR_EACH(i, set) result.set(*i, def.get_output_param_bits_count(*i));
  return result;
}


// -------------------------- gc_plain_t ---------------------

void gc_plain_t::update_from(const gc_plain_t& p2)
{
  int src = 0;
  int dst = 0;
  int count = (int)std::min(params.list.size(), p2.params.list.size());

  for (int i=0; i<count; i++)
  {
    int src_bits = p2.params.list[i];
    int dst_bits = params.list[i];

    if (src_bits && dst_bits)
    {
      assert(src_bits==dst_bits);
      for (int j=0; j<src_bits; j++) buf[dst+j] = p2.buf[src+j];
    }

    src += src_bits;
    dst += dst_bits;
  }
}

gc_plain_t operator | (const gc_plain_t& p1, const gc_plain_t& p2)
{
  gc_plain_t result(p1.params | p2.params);
  result.update_from(p1);
  result.update_from(p2);
  return result;
}

gc_plain_t operator & (const gc_plain_t& p1, const gc_params_t& p2)
{
  gc_plain_t result(p1.params & p2);
  result.update_from(p1);
  return result;
}

gc_plain_t operator - (const gc_plain_t& p1, const gc_params_t& p2)
{
  gc_plain_t result(p1.params - p2);
  result.update_from(p1);
  return result;
}

void gc_plain_t::set_param_bits(int param_index, const ub::bits_t& value)
{
  assert(param_index<(int)params.list.size());
  int count = params.list[param_index];
  assert(count==value.count());

  int offset = 0;
  for (int i=0; i<param_index; i++) offset += params.list[i];
  for (int i=0; i<count; i++) buf[offset++] = value[i];
}

ub::bits_t gc_plain_t::get_param_bits(int param_index) const
{
  assert(param_index<(int)params.list.size());
  int offset = 0;

  int count = params.list[param_index];
  ub::bits_t result(count);

  for (int i=0; i<param_index; i++) offset += params.list[i];
  for (int i=0; i<count; i++) result[i] = buf[offset++];
  return result;
}

void gc_plain_t::set_param(int param_index, mem_t value)
{
  assert(param_index<(int)params.list.size());
  int count = params.list[param_index];

  assert(ub::bits_to_bytes(count)==value.size);

  int offset = 0;
  for (int i=0; i<param_index; i++) offset += params.list[i];
  for (int i=0; i<count; i++) buf[offset++] = circuit_def_t::get_bit(value.data, i);
}

buf_t gc_plain_t::get_param(int param_index) const
{
  assert(param_index<(int)params.list.size());
  int count = params.list[param_index];

  int offset = 0;
  for (int i=0; i<param_index; i++) offset += params.list[i];

  buf_t result(ub::bits_to_bytes(count)); result.bzero();
  for (int i=0; i<count; i++) circuit_def_t::set_bit(result.data(), i, buf[offset++]);

  return result;
}



// -------------------------- gc_labels_t ---------------------

void gc_labels_t::update_from(const gc_labels_t& p2)
{
  const buf128_t* src = p2.buf.data();
  buf128_t*  dst = buf.data();
  int count = (int)std::min(params.list.size(), p2.params.list.size());

  for (int i=0; i<count; i++)
  {
    int src_bits = p2.params.list[i];
    int dst_bits = params.list[i];

    if (src_bits && dst_bits)
    {
      assert(src_bits==dst_bits);
      memmove(dst, src, src_bits * sizeof(buf128_t));
    }

    src += src_bits;
    dst += dst_bits;
  }
}

gc_labels_t operator | (const gc_labels_t& p1, const gc_labels_t& p2)
{
  gc_labels_t result(p1.params | p2.params);
  result.update_from(p1);
  result.update_from(p2);
  return result;
}

gc_labels_t operator & (const gc_labels_t& p1, const gc_params_t& p2)
{
  gc_labels_t result(p1.params & p2);
  result.update_from(p1);
  return result;
}

gc_labels_t operator - (const gc_labels_t& p1, const gc_params_t& p2)
{
  gc_labels_t result(p1.params - p2);
  result.update_from(p1);
  return result;
}

gc_labels_t gc_labels_t::get_labels_for_all_one(buf128_t delta) const
{
  gc_labels_t result = *this;
  for (int i=0; i<buf.size(); i++) result.buf[i] = buf[i] ^ delta;
  return result;
}

gc_translation_t gc_labels_t::get_translation_table() const
{
  gc_translation_t result(params);
  ub::bits_t& dst = result.get_buffer();
  dst.bzero();

  for (int i=0; i<buf.size(); i++)
  {
    dst[i] = get_label_lsb(buf[i]);
  }

  return result;
}

ub::bufs128_t gc_labels_t::encode(const ub::bufs128_t& src, buf128_t delta, mem_t data) // static
{
  assert(ub::bits_to_bytes(src.size())==data.size);
  ub::bufs128_t dst = src;
  for (int i=0; i<src.size(); i++)
  {
    if (circuit_def_t::get_bit(data.data, i)) dst[i] ^= delta;
  }
  return dst;
}

ub::bufs128_t gc_labels_t::encode(const ub::bufs128_t& src, buf128_t delta, const ub::bits_t& data)
{
  assert(data.count()==src.size());
  ub::bufs128_t dst = src;
  for (int i=0; i<src.size(); i++)
  {
    if (data[i]) dst[i] ^= delta;
  }
  return dst;
}

gc_labels_t gc_labels_t::encode(buf128_t delta, const gc_plain_t& plain) const
{
  assert(params==plain.get_params());

  gc_labels_t result = *this;
  const ub::bits_t& plain_buf = plain.get_buffer();
  result.buf = encode(buf, delta, plain_buf);
  return result;
}

gc_plain_t gc_labels_t::decode(const gc_translation_t& translation) const
{
  assert(params==translation.get_params());
  gc_plain_t result(params);
  const ub::bits_t& translation_buf = translation.get_buffer();
  ub::bits_t& result_buf = result.get_buffer();

  for (int i=0; i<buf.size(); i++)
  {
    bool tt_bit = translation_buf[i];
    bool bit = get_label_lsb(buf[i]);
    result_buf[i] = bit ^ tt_bit;
  }

  return result;
}

ub::bufs128_t gc_labels_t::get_param_labels(int param_index) const
{
  gc_labels_range_t range = get_param_labels_range(param_index);
  ub::bufs128_t result(range.size);
  memmove(result.data(), range.data, sizeof(buf128_t)*range.size);
  return result;  
}

gc_labels_range_t gc_labels_t::get_param_labels_range(int param_index) const
{
  assert(params.contains(param_index));
  gc_labels_range_t result;
  
  int offset = 0;
  for (int i=0; i<param_index; i++) offset += params.list[i];

  result.data = const_cast<buf128_t*>(buf.data()) + offset;
  result.size = params.list[param_index];
  return result;
}


// ---------------------------------------------------------------------
enum { rnd_purpose_delta = 1, rnd_purpose_input_key = 2, rnd_purpose_shared_key = 3 };

static buf128_t oword_from_purpose(int wire, int purpose)
{
  uint64_t x = (uint64_t(purpose) << 16) | wire;
  return buf128_t::make_le(x);
}


void mpc_garble_circuit(
  /* in  */ const circuit_def_t&       def, 
  /* in  */       buf128_t             seed, 
  /* out */       ub::bufs128_t&       garbled_circuit, 
  /* out */       gc_labels_t&         input_labels, 
  /* out */       gc_labels_t&         output_labels,
  /* out */       buf128_t&            delta)
{
  crypto::aes_enc128_t aes_key(seed);
  delta = aes_key.encrypt(oword_from_purpose(0, rnd_purpose_delta));
  delta |= buf128_t::make_le(1);

  const std::vector<circuit_def_t::gate_t>& gates = def.get_gates();
  int n_gates = (int)gates.size();
  int n_and_gates = def.get_n_and_gates();
  int n_wires = def.get_n_wires();

  garbled_circuit.allocate(n_and_gates*2);
  ub::bufs128_t working_wires(n_wires);

  const auto& input_wires = def.get_input_params();
  gc_params_t input_params(input_wires);
  input_labels = gc_labels_t(input_params);
  auto& input_buffer = input_labels.get_buffer();

  int offset = 0;
  FOR_EACH(param, input_wires)
  {
    const circuit_def_t::wires_t& wires = *param;
    FOR_EACH(wire, wires) input_buffer[offset++] = working_wires[*wire] = aes_key.encrypt(oword_from_purpose(*wire, rnd_purpose_input_key));
  }

  garbled_circuit_t::garble(n_gates, &gates[0], garbled_circuit.data(), working_wires.data(), delta);

  const auto& output_wires = def.get_output_params();
  gc_params_t output_params(output_wires);
  output_labels = gc_labels_t(output_params);
  auto& output_buffer = output_labels.get_buffer();
  
  offset = 0;
  FOR_EACH(param, output_wires)
  {
    const circuit_def_t::wires_t& wires = *param;
    FOR_EACH(wire, wires) output_buffer[offset++] = working_wires[*wire];
  }
}

error_t mpc_evaluate_garbled_circuit(
  /* in  */ const circuit_def_t&       def, 
  /* in  */ const ub::bufs128_t&       garbled_circuit, 
  /* in  */ const gc_labels_t&         input_labels, 
  /* out */       gc_labels_t&         output_labels)
{
  error_t rv = 0;
  const std::vector<circuit_def_t::gate_t>& gates = def.get_gates();
  int n_gates = (int)gates.size();
  int n_and_gates = def.get_n_and_gates();
  int n_wires = def.get_n_wires();

  if (garbled_circuit.size()!=n_and_gates*2) return rv = ub::error(E_BADARG);

  const std::vector<circuit_def_t::wires_t>& input_wires = def.get_input_params();
  gc_params_t input_params(input_wires);
  if (input_labels.get_params()!=input_params) return rv = ub::error(E_BADARG);

  ub::bufs128_t working_wires(n_wires);
  const auto& input_buffer = input_labels.get_buffer();

  int offset = 0;
  FOR_EACH(param, input_wires)
  {
    const circuit_def_t::wires_t& wires = *param;
    FOR_EACH(wire, wires) working_wires[*wire] = input_buffer[offset++];
  }

  garbled_circuit_t::evaluate(n_gates, &gates[0], garbled_circuit.data(), working_wires.data());

  const std::vector<circuit_def_t::wires_t>& output_wires = def.get_output_params();
  gc_params_t output_params(output_wires);
  output_labels = gc_labels_t(output_params);
  auto& output_buffer = output_labels.get_buffer();

  offset = 0;
  FOR_EACH(param, output_wires)
  {
    const circuit_def_t::wires_t& wires = *param;
    FOR_EACH(wire, wires) output_buffer[offset++] = working_wires[*wire];
  }
  return 0;
}


// -------------------------------- dual execution --------------------------------------

gc_labels_t dual_execution_core_t::get_input_labels(const gc_param_type_e type, const mpc_circuit_def_t& def, const garbling_result_t& result) 
{
  auto params = def.get_input_params(type);
  return result.input_params_labels & params;
}

gc_labels_t dual_execution_core_t::get_output_labels(const gc_param_type_e type, const mpc_circuit_def_t& def, const garbling_result_t& result) 
{
  auto params  = def.get_output_params(type);
  return result.output_params_labels & params;
}


gc_translation_t dual_execution_core_t::create_translation_table(gc_param_type_e param, const mpc_circuit_def_t& def, const garbling_result_t& result)
{
   gc_labels_t zero_labels = get_output_labels(param,def,result);
   return zero_labels.get_translation_table();
}

gc_labels_t dual_execution_core_t::encode_input(gc_param_type_e param, const mpc_circuit_def_t& def, const gc_plain_t& input, const garbling_result_t& result) 
{
  gc_labels_t zero_labels = get_input_labels(param,def,result);
  gc_labels_t labels      = zero_labels.encode(result.delta,input);
  
  return labels;
}

// checked
gc_labels_t dual_execution_core_t::encode_output(gc_param_type_e param, const mpc_circuit_def_t& def, const gc_plain_t& output, const garbling_result_t& result) 
{
  gc_labels_t zero_labels = get_output_labels(param,def,result);
  gc_labels_t labels      = zero_labels.encode(result.delta,output);
  
  return labels;
}


//gc_labels_t dual_execution::get_input_labels
//checked
dual_execution_garble_t dual_execution_core_t::init_garbling(bool is_gc_party_1, garbling_result_t& garble_result, const mpc_circuit_def_t& def, 
                                                      const gc_plain_t& input)
{
  

  gc_param_type_e self_type_param                    = is_gc_party_1 ? gc_param_type_e::party1 : gc_param_type_e::party2;
  gc_param_type_e partner_type_param                 = is_gc_party_1 ? gc_param_type_e::party2 : gc_param_type_e::party1;
  gc_param_type_e shared_type_param                  = gc_param_type_e::party12;

  auto params_input_partner                 = def.get_input_params(partner_type_param);
  auto params_input_shared                  = def.get_input_params(shared_type_param);
  auto params_input_self                    = def.get_input_params(self_type_param);

  dual_execution_garble_t dual;

  /********************************************************/
  //garble circuit
  garble_result = mpc_garble_circuit(def.get_def());
  dual.myGarble = garble_result.garbled_circuit;
  dual.delta    = garble_result.delta;

  /********************************************************/
  //input_labels

  gc_labels_t partner_labels_zero = get_input_labels(partner_type_param,def,garble_result);
  dual.his_input_keys_m0          = partner_labels_zero.get_buffer();
  dual.his_input_keys_m1          = partner_labels_zero.get_labels_for_all_one(garble_result.delta).get_buffer(); 

  auto my_input          = input & params_input_self;
  auto shared_input      = input & params_input_shared;

  dual.myEncodedInput_myGarbled   = encode_input(self_type_param,def,my_input,garble_result) 
                                  | encode_input(shared_type_param,def,shared_input,garble_result);

  dual.hisEncodedInput_hisGarble  = gc_labels_t(params_input_partner) 
                                  | gc_labels_t(params_input_shared);
  
  dual.my_input_bits_hisGarble    = my_input.get_buffer();

  /********************************************************/
  // translation table
  //auto g = [=](gc_param_type_e type){return create_translation_table(type,def,garble_result);};
  //auto h = [=](gc_param_type_e type){return def.get_output_params(type);};

  dual.translation_myGarble = create_translation_table(partner_type_param,def,garble_result) | create_translation_table(shared_type_param,def,garble_result);
  dual.translation_hisGarble  =  gc_translation_t(def.get_output_params(self_type_param) | def.get_output_params(shared_type_param));
  

  return dual;
}

error_t dual_execution_core_t::get_encoded_output(mpc_circuit_def_t& def, const dual_execution_garble_t& dual, bool is_gc_party_1, gc_labels_t& output)
{
  int rv = 0;

  auto self_param     = is_gc_party_1 ? gc_param_type_e::party1 : gc_param_type_e::party2;
  auto partner_param  = is_gc_party_1 ? gc_param_type_e::party2 : gc_param_type_e::party1;

  gc_labels_t my_encoded_input(def.get_input_params(self_param), dual.myEncodedInput_hisGarble);
  gc_labels_t his_encoded_input         = dual.hisEncodedInput_hisGarble;
  gc_labels_t inputs = his_encoded_input | my_encoded_input;

  if(rv = mpc_evaluate_garbled_circuit(def.get_def(),dual.hisGarble, inputs, output)) return rv;

  return 0;
}

garbling_result_t dual_execution_core_t::mpc_garble_circuit(const circuit_def_t& def)
{
  buf128_t seed = buf128_t::rand(); 
  garbling_result_t result;
  ::mpc_garble_circuit(def,seed,result.garbled_circuit,result.input_params_labels,result.output_params_labels,result.delta);
  return result;
}

static std::string buf256_to_hex(buf256_t input) { return strext::to_hex(mem_t(input)); }
static std::string buf128_to_hex(buf128_t input) { return strext::to_hex(mem_t(input)); }



error_t dual_execution_core_t::evaluation(mpc_circuit_def_t& def, dual_execution_garble_t& dual, bool is_gc_party_1, const garbling_result_t& result,
                                   evaluation_info_t& ev_info, buf256_t& out_hash)
{
  error_t rv = 0;

  auto self_param       = is_gc_party_1 ? gc_param_type_e::party1 : gc_param_type_e::party2;
  auto partner_param    = is_gc_party_1 ? gc_param_type_e::party2 : gc_param_type_e::party1;
  auto shared_param     = gc_param_type_e::party12;

  auto self_output_params     = def.get_output_params(self_param);
  auto partner_output_params  = def.get_output_params(partner_param);
  auto shared_output_params   = def.get_output_params(shared_param);

  

  /******************************************************************/
  // evaluate the circuit to get output

  gc_labels_t output_labels(self_output_params | partner_output_params | shared_output_params);
  if(rv = get_encoded_output(def,dual,is_gc_party_1,output_labels)) return rv;

  gc_labels_t self_output_labels    = output_labels & self_output_params;
  gc_labels_t partner_output_labels = output_labels & partner_output_params;
  gc_labels_t shared_output_labels  = output_labels & shared_output_params;

  gc_plain_t my_output     = self_output_labels.decode(dual.translation_hisGarble & self_output_params);
  gc_plain_t shared_output = shared_output_labels.decode(dual.translation_hisGarble & shared_output_params );


  /******************************************************************/
  // output validation phase

  auto my_encoded_output        = encode_output(self_param,def,my_output,result);
  auto my_shared_encoded_output = encode_output(shared_param,def,shared_output,result); 

  auto his_encoded_output        = partner_output_labels;
  auto his_shared_encoded_output = shared_output_labels;

  auto encoding_mine = my_encoded_output   | my_shared_encoded_output;
  auto encoding_his  = his_encoded_output  | his_shared_encoded_output;

  //modify hash to do hash of concatenation, don't forget to switch the order

  auto h1 = sha256_t::hash(encoding_mine.get_buffer());
  auto h2 = sha256_t::hash(encoding_his.get_buffer());
  out_hash = is_gc_party_1 ? sha256_t::hash(h1, h2) : sha256_t::hash(h2, h1);  

  ev_info.my_output = my_output;
  ev_info.shared_output = shared_output;
  ev_info.output_labels = output_labels;

  return rv;
}

void dual_execution_core_t::handle_evaluation_info(mpc_circuit_def_t& def, const evaluation_info_t& ev_info, gc_plain_t& output)
{
  output = ev_info.my_output | ev_info.shared_output;
}


// ------------------------ gc_2party_t::ot_transmit_t -------------------------

error_t gc_2party_t::ot_transmit_t::receiver_step1(mpc::ot_receiver_t* ot_receiver, const ub::bits_t& receiver_bits, message1_t& out)
{
  error_t rv = 0;
  int count = receiver_bits.count();
  if (ot_receiver->index + count > (int)ot_receiver->blocks.size() * 128) return rv = ub::error(E_UNAVAILABLE);

  out.cc.resize(count);
  rec_info.resize(count);

  for (int i = 0; i<count; i++)
  {
    out.cc[i] = ot_receiver->get_info(receiver_bits[i], rec_info[i]);
  }

  return 0;
}

error_t gc_2party_t::ot_transmit_t::sender_step2(mpc::ot_sender_t* ot_sender, const ub::bufs128_t& sender_m0, const ub::bufs128_t& sender_m1, const message1_t& in, message2_t& out)
{
  const int enc_item_size = sizeof(buf128_t)*2;
  error_t rv = 0;
  int count = in.cc.count();
  if (ot_sender->index + count > (int)ot_sender->blocks.size() * 128) return rv = ub::error(E_UNAVAILABLE);

  byte_ptr p = out.encs.resize(count*enc_item_size);

  for (int i = 0; i<count; i++)
  {
    mpc::ot_sender_info_t sen_info;
    ot_sender->get_info(sen_info);   
    mem_t m0 = sender_m0[i];
    mem_t m1 = sender_m1[i];

    //buf_t enc = sen_info.prepare_one_of_two(in.cc[i], m0, m1);
    //out.encs[i] = buf128_t::load(enc.data());
    sen_info.prepare_one_of_two(in.cc[i], m0, m1, p);
    p += enc_item_size;
  }

  return 0;
}

error_t gc_2party_t::ot_transmit_t::receiver_step3(mpc::ot_receiver_t* ot_receiver, const message2_t& in, ub::bufs128_t& result)
{
  const int enc_item_size = sizeof(buf128_t)*2;
  error_t rv = 0;
  int count = in.encs.size() / enc_item_size;
  if (count!=(int)rec_info.size()) return rv = ub::error(E_BADARG);
  result.allocate(count);

  const_byte_ptr p = in.encs.data();

  for (int i = 0; i<count; i++)
  {
    //buf_t enc = mem_t(in.encs[i]);
    buf_t dec = rec_info[i].get_one_of_two(mem_t(p, enc_item_size));
    result[i] = buf128_t::load(dec.data());
    p += enc_item_size;
  }

  return 0;
}

// ------------------------ gc_2party_t -------------------------

void gc_2party_t::convert(ub::converter_t& converter)
{

  converter.convert(is_gc_party_1);
  
  if (def)
  {
    if (!converter.is_write()) init_def();

    converter.convert(ot1);
    converter.convert(ot2);
    converter.convert(eq_test);
    converter.convert(dual);
    converter.convert(result);

    converter.convert(output_labels);
    converter.convert(ev_info_valid);
    if (ev_info_valid) 
    {
      converter.convert(ev_info);
      converter.convert(unverified_output);
    }

    converter.convert(input);

    converter.convert(output_present);
    if (output_present)
    {
      converter.convert(output);
    }

    converter.convert(comm_hash);
    converter.convert(comm_rand);
    converter.convert(test_label);
  }
}


void gc_2party_t::init(bool is_gc_party_1, mpc_circuit_def_t* def, 
    mpc::ot_sender_t* ot_sender, mpc::ot_receiver_t* ot_receiver,
    const gc_plain_t& input)
{
  this->is_gc_party_1 = is_gc_party_1;
  this->def = def;
  this->ot_sender = ot_sender;
  this->ot_receiver = ot_receiver;
  this->input = input;

  dual = dual_execution_core_t::init_garbling(is_gc_party_1,result,*def,input);
}

void gc_2party_t::init_def()
{
  gc_param_type_e self_type_param                    = is_gc_party_1 ? gc_param_type_e::party1 : gc_param_type_e::party2;
  gc_param_type_e partner_type_param                 = is_gc_party_1 ? gc_param_type_e::party2 : gc_param_type_e::party1;
  gc_param_type_e shared_type_param                  = gc_param_type_e::party12;

  auto params_input_partner                 = def->get_input_params(partner_type_param);
  auto params_input_shared                  = def->get_input_params(shared_type_param);
  auto params_input_self                    = def->get_input_params(self_type_param);

  auto params_output_partner                 = def->get_output_params(partner_type_param);
  auto params_output_shared                  = def->get_output_params(shared_type_param);
  auto params_output_self                    = def->get_output_params(self_type_param);

  input = gc_plain_t(params_input_self | params_input_shared);
  output = gc_plain_t(params_output_self | params_output_shared);
  unverified_output = gc_plain_t(params_output_self | params_output_shared);

  result.input_params_labels = gc_labels_t(def->get_def().get_input_params());
  result.output_params_labels = gc_labels_t(def->get_def().get_output_params());

  ev_info.my_output = gc_plain_t(params_output_self);
  ev_info.shared_output = gc_plain_t(params_output_shared);
  ev_info.output_labels = gc_labels_t(params_output_self | params_output_partner | params_output_shared);

  dual.myEncodedInput_myGarbled =   gc_labels_t(params_input_self | params_input_shared);
  dual.hisEncodedInput_hisGarble  = gc_labels_t(params_input_partner | params_input_shared);
  dual.translation_myGarble = gc_plain_t(params_output_partner | params_output_shared);
  dual.hisEncodedInput_hisGarble = gc_labels_t(params_input_partner | params_input_shared);
  dual.translation_hisGarble = gc_plain_t(params_output_self | params_output_shared);
}

// peer_1 garble
error_t gc_2party_t::peer1_step1(message1_t& out)
{
  assert(is_gc_party_1);

  error_t rv = 0;
  if (rv = ot2.receiver_step1(ot_receiver, dual.my_input_bits_hisGarble, out.ot2_message1)) return rv;

  return 0;
}

// peer2 garble and receive garble
error_t gc_2party_t::peer2_step2(const message1_t& in, message2_t& out) // step 2
{
  assert(!is_gc_party_1);

  error_t rv = 0;
  if (rv = ot1.receiver_step1(ot_receiver, dual.my_input_bits_hisGarble, out.ot1_message1)) return rv;
  if (rv = ot2.sender_step2(ot_sender, dual.his_input_keys_m0, dual.his_input_keys_m1, in.ot2_message1, out.ot2_message2)) return rv;

  out.garble = std::move(dual.myGarble);
  out.translation = dual.translation_myGarble.get_buffer();
  out.encoded_input = dual.myEncodedInput_myGarbled.get_buffer();

  return 0;
}

error_t gc_2party_t::peer1_step3(const message2_t& in, message3_t& out) // step 3
{
  assert(is_gc_party_1);

  error_t rv = 0;

  out.garble = std::move(dual.myGarble);
  out.translation = dual.translation_myGarble.get_buffer();
  out.encoded_input = dual.myEncodedInput_myGarbled.get_buffer();

  if (rv = ot1.sender_step2(ot_sender, dual.his_input_keys_m0, dual.his_input_keys_m1, in.ot1_message1, out.ot1_message2)) return rv;
  if (rv = ot2.receiver_step3(ot_receiver, in.ot2_message2, dual.myEncodedInput_hisGarble)) return rv;

  gc_params_t params_input_partner   = def->get_input_params(gc_param_type_e::party2);
  gc_params_t params_input_shared    = def->get_input_params(gc_param_type_e::party12);
  gc_params_t params_output_shared   = def->get_output_params(gc_param_type_e::party12);
  gc_params_t params_output_self     = def->get_output_params(gc_param_type_e::party1);

  gc_params_t param_translation_hisGarble = params_output_self | params_output_shared;
  gc_params_t param_hisEncodedInput_hisGarble = params_input_partner | params_input_shared;

  if (param_translation_hisGarble.get_bits_count()!=in.translation.count()) return rv = ub::error(E_BADARG);
  if (param_hisEncodedInput_hisGarble.get_bits_count()!=in.encoded_input.size()) return rv = ub::error(E_BADARG);

  dual.hisGarble  = std::move(in.garble);
  dual.translation_hisGarble = gc_translation_t(param_translation_hisGarble, in.translation);
  dual.hisEncodedInput_hisGarble = gc_labels_t(param_hisEncodedInput_hisGarble, in.encoded_input);

  buf256_t equality_test_hash;
  if (rv = dual_execution_core_t::evaluation(*def, dual, is_gc_party_1, result, ev_info, equality_test_hash)) return rv;

  ev_info_valid = true;
  dual.hisGarble.free();
  unverified_output = ev_info.my_output|ev_info.shared_output;

  // start equality_test
  eq_test.init(mem_t(equality_test_hash));
  eq_test.peer1_step1(out.eq_test_message1);
  return 0;
}

error_t gc_2party_t::peer2_step4(const message3_t& in, message4_t& out) // step 4
{
  assert(!is_gc_party_1);

  error_t rv = 0;
  if (rv = ot1.receiver_step3(ot_receiver, in.ot1_message2, dual.myEncodedInput_hisGarble)) return rv;

  gc_params_t params_input_partner                 = def->get_input_params(gc_param_type_e::party1);
  gc_params_t params_input_shared                  = def->get_input_params(gc_param_type_e::party12);
  gc_params_t params_output_shared                 = def->get_output_params(gc_param_type_e::party12);
  gc_params_t params_output_self                   = def->get_output_params(gc_param_type_e::party2);

  gc_params_t param_translation_hisGarble = params_output_self | params_output_shared;
  gc_params_t param_hisEncodedInput_hisGarble = params_input_partner | params_input_shared;

  if (param_translation_hisGarble.get_bits_count()!=in.translation.count()) return rv = ub::error(E_BADARG);
  if (param_hisEncodedInput_hisGarble.get_bits_count()!=in.encoded_input.size()) return rv = ub::error(E_BADARG);

  dual.hisGarble  = std::move(in.garble);
  dual.translation_hisGarble = gc_translation_t(param_translation_hisGarble, in.translation);
  dual.hisEncodedInput_hisGarble = gc_labels_t(param_hisEncodedInput_hisGarble, in.encoded_input);

  buf256_t equality_test_hash;
  if (rv = dual_execution_core_t::evaluation(*def, dual, is_gc_party_1, result, ev_info, equality_test_hash)) return rv;

  ev_info_valid = true;
  dual.hisGarble.free();
  unverified_output = ev_info.my_output|ev_info.shared_output;

  // start equality_test
  eq_test.init(mem_t(equality_test_hash));
  if (rv = eq_test.peer2_step1(in.eq_test_message1, out)) return rv;

  return 0;
}

error_t gc_2party_t::peer1_step5(const message4_t& in, message5_t& out) // step 5
{
  assert(is_gc_party_1);
  error_t rv = 0;
  bool result;
  if (rv = eq_test.peer1_step2(in, out, result)) return rv;
  if (!result) return rv = ub::error(E_CRYPTO);

  dual_execution_core_t::handle_evaluation_info(*def, ev_info, output);
  output_present = true;
  return 0;
}

error_t gc_2party_t::peer2_step6(const message5_t& in) // step 6
{
  assert(!is_gc_party_1);
  error_t rv = 0;
  bool result;
  if (rv = eq_test.peer2_step2(in, result)) return rv;
  if (!result) return rv = ub::error(E_CRYPTO);

  dual_execution_core_t::handle_evaluation_info(*def, ev_info, output);
  output_present = true;
  return 0;
}
