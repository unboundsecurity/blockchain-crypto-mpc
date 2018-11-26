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
#include "crypto.h"
#include "crypto_aesni.h"


enum { gc_true=INT_MAX, gc_false=INT_MAX-1 };

class circuit_def_t
{
  friend class garbled_circuit_t;

public:
  class wires_t : public std::vector<int>
  {
  public:
    wires_t() {}
    explicit wires_t(int count) { init(count); }
    void init(int count);
    void swap_bits();
    void swap_bytes();
  };

public:
  enum gate_type_t { gate_type_none=0, gate_type_not=1, gate_type_xor=2, gate_type_and=3 };

  struct gate_t
  {
    gate_type_t type;
    int input0;
    int input1;
    int output;
  };

  circuit_def_t();
  ~circuit_def_t();
  bool empty() const { return n_wires==0; }
  int get_and_gates_count() const { return n_and_gates; }
  int get_input_param_bits_count(int par_index) const { return (int)input_params[par_index].size(); }
  int get_output_param_bits_count(int par_index) const { return (int)output_params[par_index].size(); }

  static bool get_bit(const_byte_ptr data, int bit_index);
  static void set_bit(byte_ptr data, int bit_index, bool bit);
  static void copy_bits(byte_ptr dst, int dst_index, const_byte_ptr src, int src_index, int count);
  static void push_bits(byte_ptr dst, int &dst_index, const_byte_ptr src, int src_index, int count) { copy_bits(dst, dst_index, src, src_index, count); dst_index += count; }

  int set_input_param(const wires_t& wires);
  int set_output_param(const wires_t& wires);
  int set_input_param(int wire);
  int set_output_param(int wire);

  int get_wire_true();
  int get_wire_false();
  int get_const_wire(bool value) { return value ? get_wire_true() : get_wire_false(); }

  int or_gate(int& w1, int& w2)  { return or_gate(-1, w1, w2); }
  int or_gate(int res, int& w1, int& w2);
  int or_func(int w1, int w2) { assert(w1 != -1 && w2 != -1);  return or_gate(w1, w2); }

  int xor_gate(int& w1, int& w2)  { return xor_gate(-1, w1, w2); }
  int xor_gate(int res, int& w1, int& w2);
  int xor_known(int w1, int w2) { assert(w1 != -1 && w2 != -1);  return xor_gate(w1, w2); }

  int and_gate(int& w1, int& w2)  { return and_gate(-1, w1, w2); }
  int and_gate(int res, int& w1, int& w2);
  int and_known(int w1, int w2) { assert(w1 != -1 && w2 != -1);  return and_gate(w1, w2); }

  int not_gate(int& w1) { return not_gate(-1, w1); }
  int not_gate(int res, int& w1);
  int not_known(int w1) { assert(w1 != -1); return not_gate(w1); }

  void xor_gates(wires_t& dst, wires_t& src1, wires_t& src2);
  void xor_gates(wires_t& dst, wires_t& src);
  void xor_gates_known(wires_t& dst, const wires_t& src1, const wires_t& src2);
  void xor_gates_known(wires_t& dst, const wires_t& src);

  void and_gates(wires_t& dst, wires_t& src1, wires_t& src2);
  void and_gates(wires_t& dst, wires_t& src);
  void and_gates_known(wires_t& dst, const wires_t& src1, const wires_t& src2);
  void and_gates_known(wires_t& dst, const wires_t& src);

  void not_gates(wires_t& dst, wires_t& src);
  void not_gates(wires_t& dst);
  void not_gates_known(wires_t& dst, const wires_t& src);

  void update_wires(wires_t& wires);
  void update_wire(int& wire);

  void build_add(wires_t* dst, wires_t& a, wires_t& b, int* s_flag=0, int* nz_flag=0);
  int build_sub(wires_t& out, wires_t& X, wires_t& Y);
  int build_gt(wires_t& a, wires_t& b, bool is_signed=false, bool big_endian=false);
  void load_compressed(const_byte_ptr bin, wires_t& out, wires_t& in1, wires_t& in2);

  const std::vector<gate_t>& get_gates() const { return gates; }
  int get_n_wires() const { return n_wires; }
  int get_n_and_gates() const { return n_and_gates; }

  const std::vector<wires_t>& get_input_params() const { return input_params; }
  const std::vector<wires_t>& get_output_params() const { return output_params; }

private:
  std::vector<gate_t> gates;

  int n_wires;
  int n_and_gates;
  int wire_true;
  int wire_false;

  std::vector<wires_t> input_params;
  std::vector<wires_t> output_params;

  void add_gate(gate_type_t type, int out, int in1, int in2);
  static void update_input_wire(int& wire, wires_t& in1, wires_t& in2, int offset);
  void resolve_const_wires(wires_t& wires);
};


class garbled_circuit_t
{
public:

  static void garble(int n_gates, const circuit_def_t::gate_t* gates, buf128_t* garbled, buf128_t* wires, buf128_t delta);
  static void evaluate(int n_gates, const circuit_def_t::gate_t* gates, const buf128_t* garbled, buf128_t* wires);

  typedef buf128_t wire_t;

  struct gate_t
  {
    wire_t input0;
    wire_t input1;
    wire_t& output;
    //int index;
    gate_t(wire_t _input0, wire_t _input1, wire_t& _output/*, int _index*/) : input0(_input0), input1(_input1), output(_output)/*, index(_index)*/ {}
    gate_t(wire_t _input0, wire_t& _output/*, int _index*/) : input0(_input0), output(_output)/*, index(_index)*/ {}
  };

  static crypto::aes_enc128_t fixed_aes_key;
};


