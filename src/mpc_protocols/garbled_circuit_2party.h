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

#include "ub_convert.h"
#include "garbled_circuit.h"
#include "crypto_aesni.h"
#include "mpc_ot.h"
#include "mpc_ecc_core.h"

enum class gc_param_type_e
{
  none,
  party1,
  party2,
  party12,
  max
};

class gc_params_t
{
  friend class gc_labels_t;
  friend class gc_plain_t;

public:
  gc_params_t() {}
  gc_params_t(int param_index, int param_bits) { set(param_index, param_bits); }
  gc_params_t(const std::vector<circuit_def_t::wires_t>& wires);
  
  int get_bits_count() const;
  void set(int param_index, int param_bits);
  void clear() { list.clear(); }

  friend gc_params_t operator | (const gc_params_t& p1, const gc_params_t& p2);
  friend gc_params_t operator & (const gc_params_t& p1, const gc_params_t& p2);
  friend gc_params_t operator - (const gc_params_t& p1, const gc_params_t& p2);
  
  gc_params_t& operator |= (const gc_params_t& p2) { return *this = *this | p2; }
  gc_params_t& operator &= (const gc_params_t& p2) { return *this = *this & p2; }
  gc_params_t& operator -= (const gc_params_t& p2) { return *this = *this - p2; }
  bool operator == (const gc_params_t& p2) const { return equ(*this, p2); }
  bool operator != (const gc_params_t& p2) const { return !equ(*this, p2); }

  bool contains(int param_index) const { return (int)list.size()>param_index && list[param_index]>0; }
  int get_count() const;

private:
  std::vector<int> list;

  static bool equ(const gc_params_t& p1, const gc_params_t& p2) { return p1.list==p2.list; }
};

gc_params_t operator | (const gc_params_t& p1, const gc_params_t& p2);
gc_params_t operator & (const gc_params_t& p1, const gc_params_t& p2);
gc_params_t operator - (const gc_params_t& p1, const gc_params_t& p2);


// This class adds the information about the parameter types (gc_param_type_e) 
// to the generic circuit_def_t
class mpc_circuit_def_t
{
public:
  mpc_circuit_def_t(const circuit_def_t& _def) : def(_def) {}
  void set_input_param(int param_index, gc_param_type_e type);
  void set_output_param(int param_index, gc_param_type_e type);
  const circuit_def_t& get_def() const { return def; }

  gc_params_t get_input_param(int param_index) const;
  gc_params_t get_output_param(int param_index) const;
  gc_params_t get_input_params(gc_param_type_e type) const;
  gc_params_t get_output_params(gc_param_type_e type) const;

private:
  const circuit_def_t& def;
  std::set<int> tab_input[int(gc_param_type_e::max)];
  std::set<int> tab_output[int(gc_param_type_e::max)];
};

class gc_plain_t
{
public:
  gc_plain_t() {}
  gc_plain_t(const gc_params_t& _params) : params(_params), buf(params.get_bits_count()) { buf.bzero(); }
  gc_plain_t(const gc_params_t& _params, const ub::bits_t& _buf) : params(_params), buf(_buf) { assert(params.get_bits_count()==buf.count()); }
  ub::bits_t& get_buffer() { return buf; }
  const ub::bits_t& get_buffer() const { return buf; }

  void convert(ub::converter_t& converter) 
  { 
    converter.convert(buf); 
    if (!converter.is_write() && buf.count()!=params.get_bits_count()) converter.set_error();
  }

  void set_param(int param_index, mem_t value);
  buf_t get_param(int param_index) const;

  void set_param_bits(int param_index, const ub::bits_t& value);
  ub::bits_t get_param_bits(int param_index) const;

  friend gc_plain_t operator | (const gc_plain_t& p1, const gc_plain_t& p2);
  friend gc_plain_t operator & (const gc_plain_t& p1, const gc_params_t& p2);
  friend gc_plain_t operator - (const gc_plain_t& p1, const gc_params_t& p2);

  gc_plain_t& operator |= (const gc_plain_t& p2)  { return *this = *this | p2; }
  gc_plain_t& operator &= (const gc_params_t& p2) { return *this = *this & p2; }
  gc_plain_t& operator -= (const gc_params_t& p2) { return *this = *this - p2; }

  const gc_params_t& get_params() const { return params; }

  bool operator == (const gc_plain_t& src2) const { return params==src2.params && buf==src2.buf; }


private:
  gc_params_t params;
  ub::bits_t buf;

  void update_from(const gc_plain_t& src);
};


gc_plain_t operator | (const gc_plain_t& p1, const gc_plain_t& p2);
gc_plain_t operator & (const gc_plain_t& p1, const gc_params_t& p2);
gc_plain_t operator - (const gc_plain_t& p1, const gc_params_t& p2);


typedef gc_plain_t gc_translation_t;


struct gc_labels_range_t
{
  buf128_t* data;
  int size;
};

class gc_labels_t
{
public:
  gc_labels_t() {}
  gc_labels_t(const gc_params_t& _params) : params(_params), buf(params.get_bits_count()) { }
  gc_labels_t(const gc_params_t& _params, const ub::bufs128_t _buf) : params(_params), buf(_buf) { }
  const ub::bufs128_t& get_buffer() const { return buf; }
  ub::bufs128_t& get_buffer() { return buf; }

  void convert(ub::converter_t& converter) 
  { 
    converter.convert(buf); 
    if (!converter.is_write() && buf.size()!=params.get_bits_count()) converter.set_error();
  }

  friend gc_labels_t operator | (const gc_labels_t& p1, const gc_labels_t& p2);
  friend gc_labels_t operator & (const gc_labels_t& p1, const gc_params_t& p2);
  friend gc_labels_t operator - (const gc_labels_t& p1, const gc_params_t& p2);

  gc_labels_t& operator |= (const gc_labels_t& p2) { return *this = *this | p2; }
  gc_labels_t& operator &= (const gc_params_t& p2) { return *this = *this & p2; }
  gc_labels_t& operator -= (const gc_params_t& p2) { return *this = *this - p2; }

  const gc_params_t& get_params() const { return params; }

  // Used to get the one-labels (L0 xor Delta).
  gc_labels_t get_labels_for_all_one(buf128_t delta) const;

  // Creates translation table from labels (using least significant bit)
  gc_translation_t get_translation_table() const;

  // encode
  gc_labels_t encode(buf128_t delta, const gc_plain_t& plain) const;

  static ub::bufs128_t encode(const ub::bufs128_t& src, buf128_t delta, mem_t data);
  static ub::bufs128_t encode(const ub::bufs128_t& src, buf128_t delta, const ub::bits_t& data);

  // decode
  gc_plain_t decode(const gc_translation_t& translation) const;

  ub::bufs128_t get_param_labels(int param_index) const;
  gc_labels_range_t get_param_labels_range(int param_index) const;

  bool operator == (const gc_labels_t& src2) const { return params==src2.params && buf==src2.buf; }

private:
  gc_params_t params;
  ub::bufs128_t buf;

  void update_from(const gc_labels_t& src);

};


gc_labels_t operator | (const gc_labels_t& p1, const gc_labels_t& p2);
gc_labels_t operator & (const gc_labels_t& p1, const gc_params_t& p2);
gc_labels_t operator - (const gc_labels_t& p1, const gc_params_t& p2);



error_t mpc_evaluate_garbled_circuit(
  /* in  */ const circuit_def_t&       def, 
  /* in  */ const ub::bufs128_t&       garbled_circuit, 
  /* in  */ const gc_labels_t&         input_labels, 
  /* out */       gc_labels_t&         output_labels);

void mpc_garble_circuit(
  /* in  */ const circuit_def_t&       def, 
  /* in  */       buf128_t             seed, 
  /* out */       ub::bufs128_t&       garbled_circuit, 
  /* out */       gc_labels_t&         input_labels, 
  /* out */       gc_labels_t&         output_labels,
  /* out */       buf128_t&            delta);

// -----------------------------------------------------------------------
struct garbling_result_t
{
  ub::bufs128_t garbled_circuit;
  gc_labels_t   input_params_labels;
  gc_labels_t   output_params_labels;
  buf128_t      delta;

  void convert(ub::converter_t& converter) 
  {
    converter.convert(garbled_circuit);
    converter.convert(input_params_labels);
    converter.convert(output_params_labels);
    converter.convert(delta);
  }
};

struct dual_execution_garble_t
{
   buf128_t delta;
    
   //Garbling values produced by garbler.
   ub::bufs128_t     myGarble;                      
   gc_labels_t       myEncodedInput_myGarbled;       // Includes shared input
   gc_translation_t  translation_myGarble;
   
   // Used for oblivious transfer
   ub::bufs128_t his_input_keys_m0, his_input_keys_m1;
	 ub::bits_t my_input_bits_hisGarble;

   //Garbling values received by evaluator
	 ub::bufs128_t hisGarble;                    
   ub::bufs128_t myEncodedInput_hisGarble;     
   gc_labels_t   hisEncodedInput_hisGarble;   // Includes shared input.
   gc_translation_t translation_hisGarble; 

   void convert(ub::converter_t& converter)
   {
     converter.convert(delta);
     converter.convert(myGarble);
     converter.convert(myEncodedInput_myGarbled);
     converter.convert(translation_myGarble);
     converter.convert(his_input_keys_m0);
     converter.convert(his_input_keys_m1);
     converter.convert(my_input_bits_hisGarble);
     converter.convert(hisGarble);
     converter.convert(myEncodedInput_hisGarble);
     converter.convert(hisEncodedInput_hisGarble);
     converter.convert(translation_hisGarble);
   }
};

class gc_2party_t;

struct dual_execution_core_t
{
  friend class gc_2party_t;

protected:
  static  gc_labels_t get_input_labels(const gc_param_type_e type, const mpc_circuit_def_t & def, const garbling_result_t & result);
  static  gc_labels_t get_output_labels(const gc_param_type_e type, const mpc_circuit_def_t & def, const garbling_result_t & result);
  static  gc_labels_t encode_input(gc_param_type_e param, const mpc_circuit_def_t & def, const gc_plain_t & input, const garbling_result_t & result);
  static  gc_labels_t encode_output(gc_param_type_e param, const mpc_circuit_def_t & def, const gc_plain_t & input, const garbling_result_t & result);
  
  static dual_execution_garble_t init_garbling(bool is_gc_party_1, garbling_result_t & result, const mpc_circuit_def_t & def, const gc_plain_t & input);
  static  gc_translation_t create_translation_table(gc_param_type_e param, const mpc_circuit_def_t & def, const garbling_result_t & result);
  //static  error_t exchange_encodings(job_t & job, bool is_gc_party_1, const mpc_circuit_def_t & mpc_def, dual_execution_garble_t& dual);

  static  error_t get_encoded_output(mpc_circuit_def_t & def, const dual_execution_garble_t & dual, bool is_gc_party_1, gc_labels_t & output);
  //static  error_t equality_test(job_t & job, bool is_gc_party_1, buf256_t input);

  struct evaluation_info_t
  {
    gc_plain_t my_output, shared_output;
    gc_labels_t output_labels;
    void convert(ub::converter_t& converter)
    {
      converter.convert(my_output);
      converter.convert(shared_output);
      converter.convert(output_labels);
    }
  };

  static void handle_evaluation_info(mpc_circuit_def_t& def, const evaluation_info_t& ev_info, gc_plain_t& output);
  static error_t evaluation(mpc_circuit_def_t & def, dual_execution_garble_t & dual, bool is_gc_party_1, const garbling_result_t & result, evaluation_info_t& ev_info, buf256_t& out_hash);
  static  garbling_result_t mpc_garble_circuit(const circuit_def_t& def);

};

class gc_2party_t
{
public:
  gc_2party_t() : ev_info_valid(false), output_present(false) {}

  void init(bool is_gc_party_1, mpc_circuit_def_t* def, 
    mpc::ot_sender_t* ot_sender, mpc::ot_receiver_t* ot_receiver,
    const gc_plain_t& input);

  gc_plain_t get_output() const { return output; }

  void init_def();
  void convert(ub::converter_t& converter);

  struct ot_transmit_t
  {
    struct message1_t
    {
      ub::bits_t cc;
      void convert(ub::converter_t& converter)
      {
        converter.convert(cc);
      }
    };

    struct message2_t
    {
      buf_t encs;
      void convert(ub::converter_t& converter)
      {
        converter.convert(encs);
      }
    };

    error_t receiver_step1(mpc::ot_receiver_t* ot_receiver, const ub::bits_t& receiver_bits, message1_t& out);
    error_t sender_step2(mpc::ot_sender_t* ot_sender, const ub::bufs128_t& sender_m0, const ub::bufs128_t& sender_m1, const message1_t& in, message2_t& out);
    error_t receiver_step3(mpc::ot_receiver_t* ot_receiver, const message2_t& in, ub::bufs128_t& result);

    void convert(ub::converter_t& converter)
    {
      converter.convert(rec_info);
    }

  private:
    std::vector<mpc::ot_receiver_info_t> rec_info;
  };

  struct message1_t // 1->2
  {
    ot_transmit_t::message1_t ot2_message1;
    void convert(ub::converter_t& converter)
    {
      converter.convert(ot2_message1);
    }
  };

  struct message2_t // 2->1
  {
    ot_transmit_t::message1_t ot1_message1;
    ot_transmit_t::message2_t ot2_message2;
    ub::bufs128_t garble;
    ub::bits_t translation;
    ub::bufs128_t encoded_input;

    void convert(ub::converter_t& converter)
    {
      converter.convert(ot1_message1);
      converter.convert(ot2_message2);
      converter.convert(garble);
      converter.convert(translation);
      converter.convert(encoded_input);
    }
  };

  struct message3_t // 1->2
  {
    ot_transmit_t::message2_t ot1_message2;
    mpc::equality_test_t::message1_t eq_test_message1;
    ub::bufs128_t garble;
    ub::bits_t translation;
    ub::bufs128_t encoded_input;

    void convert(ub::converter_t& converter)
    {
      converter.convert(garble);
      converter.convert(translation);
      converter.convert(encoded_input);

      converter.convert(ot1_message2);
      converter.convert(eq_test_message1);
    }
  };

  typedef mpc::equality_test_t::message2_t message4_t; // 2->1
  typedef mpc::equality_test_t::message3_t message5_t; // 1->2

  error_t peer1_step1(message1_t& out);
  error_t peer2_step2(const message1_t& in, message2_t& out);
  error_t peer1_step3(const message2_t& in, message3_t& out);
  error_t peer2_step4(const message3_t& in, message4_t& out);
  error_t peer1_step5(const message4_t& in, message5_t& out);
  error_t peer2_step6(const message5_t& in);

public:
  mpc_circuit_def_t* def;
  mpc::ot_sender_t* ot_sender;
  mpc::ot_receiver_t* ot_receiver;
  ot_transmit_t ot1, ot2;
  dual_execution_garble_t dual;
  garbling_result_t result;

  mpc::equality_test_t eq_test;

  gc_labels_t output_labels;

  bool ev_info_valid;
  dual_execution_core_t::evaluation_info_t ev_info;

  bool is_gc_party_1;
  gc_plain_t input;

  bool output_present;
  gc_plain_t output;
  gc_plain_t unverified_output;

  buf256_t comm_hash;
  buf128_t comm_rand;
  buf128_t test_label;
};
