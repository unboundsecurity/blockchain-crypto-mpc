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
#include "ub_cpuid.h"
#include "garbled_circuit.h"

void circuit_def_t::wires_t::init(int count)
{
  resize(count, -1);
}

void circuit_def_t::wires_t::swap_bits()
{
  assert(0==(size() & 7));
  for (int i=0; i<(int)size(); i+=8)
  {
    std::swap(at(i+0), at(i+7));
    std::swap(at(i+1), at(i+6));
    std::swap(at(i+2), at(i+5));
    std::swap(at(i+3), at(i+4));
  }
}

void circuit_def_t::wires_t::swap_bytes()
{
  assert(0==(size() & 7));
  int lo = 0;
  int hi = (int)size()-8;

  while (lo<hi)
  {
    for (int i=0; i<8; i++) std::swap(at(lo+i), at(hi+i));
    lo += 8;
    hi -= 8;
  }
}

#define HALF_GATE
  
const uint8_t gc_fixed_key_value[]    = {0x28, 0xe7, 0xf6, 0xcf, 0x6e, 0x5a, 0x25, 0x3d, 0x60, 0x85, 0x88, 0x43, 0x49, 0x06, 0xfa, 0xfc};
crypto::aes_enc128_t garbled_circuit_t::fixed_aes_key(buf128_t::load(gc_fixed_key_value));

//------------------------ circuit_def_t ----------------------------

circuit_def_t::circuit_def_t() : n_and_gates(0), n_wires(0), wire_true(-1), wire_false(-1)
{  
}

circuit_def_t::~circuit_def_t()
{
}

int circuit_def_t::get_wire_true()
{
  if (wire_true==-1)
  {
    int wire_false = get_wire_false();
    wire_true = not_gate(wire_false);
  }
  return wire_true;
}

int circuit_def_t::get_wire_false()
{
  if (wire_false==-1)
  {
    assert(n_wires>0);
    int any_wire = 0;
    wire_false = xor_gate(any_wire, any_wire);
  }
  return wire_false;
}


bool circuit_def_t::get_bit(const_byte_ptr data, int index) 
{ 
  int offset = index >> 3;
  int n = index & 7;
  uint8_t mask = 1<<n;
  return (data[offset] & mask) ? true : false;
}

void circuit_def_t::set_bit(byte_ptr data, int index, bool bit) 
{ 
  int offset = index >> 3;
  int n = index & 7;
  uint8_t mask = 1<<n;
  if (bit) data[offset] |= mask;
  else data[offset] &= ~mask;
}

void circuit_def_t::copy_bits(byte_ptr dst, int dst_index, const_byte_ptr src, int src_index, int count) 
{
  for (int i = 0; i < count; i++) set_bit(dst, dst_index + i, get_bit(src, src_index+i));
}


int circuit_def_t::set_input_param(const wires_t& indices)
{
  for (int i=0; i<(int)indices.size(); i++)
  {
    assert(indices[i]>=0);
  }
  int result = (int)input_params.size(); 
  input_params.push_back(indices);
  return result;
}

int circuit_def_t::set_output_param(const wires_t& indices)
{
  for (int i=0; i<(int)indices.size(); i++)
  {
    assert(indices[i]>=0);
  }
  int result = (int)output_params.size(); 
  output_params.push_back(indices);
  return result;
}

int circuit_def_t::set_input_param(int wire)
{
  wires_t w(1); w[0] = wire;
  return set_input_param(w);
}

int circuit_def_t::set_output_param(int wire)
{
  wires_t w(1); w[0] = wire;
  return set_output_param(w);
}

void circuit_def_t::resolve_const_wires(wires_t& wires)
{
  for (int i=0; i<(int)wires.size(); i++) 
  {
    if (wires[i]==gc_true) wires[i] = get_wire_true();
    else if (wires[i]==gc_false) wires[i] = get_wire_false();
  }
}

void circuit_def_t::update_input_wire(int& wire, wires_t& in1, wires_t& in2, int offset) //static
{
  int in1_size = (int)in1.size();
  int w = wire;
  wire += offset;
  
  if (w<in1_size)
  {
    if (in1[w]<0) in1[w] = wire;
    else wire = in1[w];
    return;
  }

  w -= in1_size;
  if (w<(int)in2.size())
  {
    if (in2[w]<0) in2[w] = wire; 
    else wire = in2[w];
  }
}


static int get_compressed(const_byte_ptr& bin, int size_code)
{
  if (size_code==0) return 0;

  int v = 0;
  int n = 0;
  for (;;)
  {
    unsigned x = *bin++;
    v |= ((x & 0x7f) << n);

    if ((x & 0x80)==0) break;
    n += 7;
  }

  if (size_code==2) v = -v;
  return v;
}

void circuit_def_t::load_compressed(const_byte_ptr bin, wires_t& output, wires_t& input1, wires_t& input2)
{
  int n_in1 = ub::le_get_4(bin); bin+=4;
  int n_in2 = ub::le_get_4(bin); bin+=4;
  int n_out = ub::le_get_4(bin); bin+=4;

  assert((int)input1.size()==n_in1);
  assert((int)input2.size()==n_in2);
  assert((int)output.size()==n_out);

  update_wires(input1);
  update_wires(input2);
  resolve_const_wires(input1);
  resolve_const_wires(input2);
  int offset = n_wires;

  int old_in1 = 0;
  int old_in2 = 0;
  int old_out = 0;

  for (;;)
  {
    byte_t x = *bin++;
    gate_type_t type = (gate_type_t)(x & 3);

    int in1_size = (x >> 2) & 3;
    int in2_size = (x >> 4) & 3;
    int out_size = (x >> 6) & 3;

    if (type==gate_type_none) break;
    int in1, in2, out;

    switch (type)
    {
      case gate_type_not: 
        in1 = get_compressed(bin, in1_size) + old_in1 + 1; old_in1 = in1;
        update_input_wire(in1, input1, input2, offset);
        out = get_compressed(bin, out_size) + old_out + 1; old_out = out;
        not_gate(offset + out, in1); 
        break;

      case gate_type_and: 
        in1 = get_compressed(bin, in1_size) + old_in1 + 1; old_in1 = in1;
        update_input_wire(in1, input1, input2, offset);
        in2 = get_compressed(bin, in2_size) + old_in2 + 1; old_in2 = in2;
        update_input_wire(in2, input1, input2, offset);
        out = get_compressed(bin, out_size) + old_out + 1; old_out = out;
        and_gate(offset + out, in1, in2); 
        break;

      case gate_type_xor: 
        in1 = get_compressed(bin, in1_size) + old_in1 + 1; old_in1 = in1;
        update_input_wire(in1, input1, input2, offset);
        in2 = get_compressed(bin, in2_size) + old_in2 + 1; old_in2 = in2;
        update_input_wire(in2, input1, input2, offset);
        out = get_compressed(bin, out_size) + old_out + 1; old_out = out;
        xor_gate(offset + out, in1, in2); 
        break;

      default: assert(false);
    }    
  }

  for (int i=0; i<n_out; i++) output[i] = n_wires - n_out + i;
}

int circuit_def_t::or_gate(int res, int& w1, int& w2)
{
  if (w1==gc_true || w2==gc_true) return gc_true;
  if (w1==gc_false) return w2;
  if (w2==gc_false) return w1;

  int x1 = xor_gate(w1, w2);
  int x2 = and_gate(w1, w2);
  return xor_gate(res, x1, x2);
}

void circuit_def_t::update_wire(int& wire)
{
  if (wire == gc_true || wire == gc_false) return;
  if (wire<0) wire = n_wires;
  if (wire>=n_wires) n_wires = wire+1;
}

void circuit_def_t::update_wires(wires_t& wires)
{
  for (int i=0; i<(int)wires.size(); i++) update_wire(wires[i]);
}

void circuit_def_t::add_gate(gate_type_t type, int out, int in1, int in2)
{
  gate_t gate;
  //gate.index = n_gates;
  gate.input0 = in1;
  gate.input1 = in2;
  gate.output = out;
  gate.type = type;
  gates.push_back(gate);
  if (type==gate_type_and) n_and_gates++;
}

int circuit_def_t::xor_gate(int res, int& w1, int& w2)
{
  if (w1==gc_false) return w2;
  if (w2==gc_false) return w1;
  if (w1==gc_true) return not_gate(w2);
  if (w2==gc_true) return not_gate(w1);

  update_wire(w1);
  update_wire(w2);
  update_wire(res);
  add_gate(gate_type_xor, res, w1, w2);
  return res;
}

int circuit_def_t::and_gate(int res, int& w1, int& w2)
{
  if (w1==gc_false || w2==gc_false) return gc_false;
  if (w1==gc_true) return w2;
  if (w2==gc_true) return w1;

  update_wire(w1);
  update_wire(w2);
  update_wire(res);
  add_gate(gate_type_and, res, w1, w2);
  return res;
}

int circuit_def_t::not_gate(int res, int& w1)
{
  if (w1==gc_true) return gc_false;
  if (w1==gc_false) return gc_true;

  update_wire(res);
  add_gate(gate_type_not, res, w1, -1);
  return res;
}

void circuit_def_t::xor_gates(wires_t& dst, wires_t& src1, wires_t& src2)
{
  assert(dst.size()==src1.size());
  assert(dst.size()==src2.size());
  for (int i=0; i<(int)dst.size(); i++) 
  {
    int temp = xor_gate(src1[i], src2[i]);
    if (dst[i]==-1) dst[i] = temp;
    else dst[i] = xor_gate(dst[i], temp);
  }
}

void circuit_def_t::xor_gates_known(wires_t& dst, const wires_t& src1, const wires_t& src2)
{
  assert(dst.size() == src1.size());
  assert(dst.size() == src2.size());
  for (int i = 0; i<(int)dst.size(); i++)
  {
    int temp = xor_known(src1[i], src2[i]);
    if (dst[i] == -1) dst[i] = temp;
    else dst[i] = xor_known(dst[i], temp);
  }
}

void circuit_def_t::xor_gates(wires_t& dst, wires_t& src)
{
  assert(dst.size()==src.size());
  for (int i=0; i<(int)dst.size(); i++) 
  {
    dst[i] = xor_gate(dst[i], src[i]);
  }
}

void circuit_def_t::xor_gates_known(wires_t& dst, const wires_t& src)
{
  assert(dst.size() == src.size());
  for (int i = 0; i<(int)dst.size(); i++)
  {
    dst[i] = xor_known(dst[i], src[i]);
  }
}

void circuit_def_t::and_gates(wires_t& dst, wires_t& src1, wires_t& src2)
{
  assert(dst.size()==src1.size());
  assert(dst.size()==src2.size());
  for (int i=0; i<(int)dst.size(); i++) 
  {
    int temp = and_gate(src1[i], src2[i]);
    if (dst[i]==-1) dst[i] = temp;
    else dst[i] = and_gate(dst[i], temp);
  }
}

void circuit_def_t::and_gates_known(wires_t& dst, const wires_t& src1, const wires_t& src2)
{
  assert(dst.size() == src1.size());
  assert(dst.size() == src2.size());
  for (int i = 0; i<(int)dst.size(); i++)
  {
    int temp = and_known(src1[i], src2[i]);
    if (dst[i] == -1) dst[i] = temp;
    else dst[i] = and_known(dst[i], temp);
  }
}

void circuit_def_t::and_gates(wires_t& dst, wires_t& src)
{
  assert(dst.size()==src.size());
  for (int i=0; i<(int)dst.size(); i++) 
  {
    dst[i] = and_gate(dst[i], src[i]);
  }
}

void circuit_def_t::and_gates_known(wires_t& dst, const wires_t& src)
{
  assert(dst.size() == src.size());
  for (int i = 0; i<(int)dst.size(); i++)
  {
    dst[i] = and_known(dst[i], src[i]);
  }
}

void circuit_def_t::not_gates(wires_t& dst, wires_t& src) 
{
  assert(dst.size()==src.size());
  for (int i=0; i<(int)dst.size(); i++) 
  {
    dst[i] = not_gate(src[i]);
  }
}

void circuit_def_t::not_gates_known(wires_t& dst, const wires_t& src)
{
  assert(dst.size() == src.size());
  for (int i = 0; i<(int)dst.size(); i++)
  {
    dst[i] = not_known(src[i]);
  }
}

void circuit_def_t::not_gates(wires_t& dst)
{
  for (int i=0; i<(int)dst.size(); i++) 
  {
    dst[i] = not_gate(dst[i]);
  }
}

void circuit_def_t::build_add(wires_t* dst, wires_t& a, wires_t& b, int* s_flag, int* nz_flag)
{
  int bits = (int)a.size();
  assert((int)b.size()==bits);

  update_wires(a);
  update_wires(b);

  int c = -1;
  int res = -1;
  int res_nz = -1;

  for (int i=0; i<bits; i++) 
  {
    int a_xor_c = (i==0) ? a[i] : xor_gate(a[i], c);

    if (dst || nz_flag || i==bits-1)
    {
      res = xor_gate(a_xor_c, b[i]);
      if (dst) (*dst)[i] = res;
    }
    
    if (nz_flag)
    {
      res_nz = (i==0) ? res : or_gate(res_nz, res);
    }

    if (i==bits-1) break;

    int b_xor_c = (i==0) ? b[i] : xor_gate(b[i], c);
    int a_xor_c_and_b_xor_c = and_gate(a_xor_c, b_xor_c);
    c = (i==0) ? a_xor_c_and_b_xor_c : xor_gate(a_xor_c_and_b_xor_c, c);
  }

  if (s_flag) *s_flag = res;
  if (nz_flag) *nz_flag = res_nz;
}


int circuit_def_t::build_sub(wires_t& out, wires_t& X, wires_t& Y)
{
  int count = (int)X.size();
  assert(count==(int)Y.size());
  assert(count==(int)out.size());

  int z = -1;
  for (int i=0; i<count; i++)
  {
    // CARRY is Z
    // new Z = X XOR ((X XOR Y) OR (X XOR Z))
    // out = X XOR Y XOR Z

    int x = X[i]; int y = Y[i];
    int x_xor_y = xor_gate(x, y);
    int x_xor_z = (z==-1) ? x : xor_gate(x, z);
    out[i] = (z==-1) ? x_xor_y : xor_gate(x_xor_y, z);
    int x_xor_y_or_x_xor_z = or_gate(x_xor_y, x_xor_z);
    z = xor_gate(x, x_xor_y_or_x_xor_z);
  }
  return z;
}

int circuit_def_t::build_gt(wires_t& a, wires_t& b, bool is_signed, bool big_endian)
{
  int bits = (int)a.size();
  assert((int)b.size()==bits);

  int c = -1;
  int i = 0;
  if (big_endian) i = bits-8;

  int n = bits;

  for (int n=0; n<bits; n++)
  {
    int a_xor_b = xor_gate(a[i], b[i]);
    int a_xor_b_xor_c = a_xor_b;
    int b_xor_c = b[i];
    
    if (n>0)
    {
      a_xor_b_xor_c = xor_gate(a_xor_b, c);
      int bb = b[i];
      if (is_signed && (n==bits-1)) bb = a[i];
      b_xor_c = xor_gate(bb, c);
    }

    int a_xor_b_and_b_xor_c = and_gate(a_xor_b, b_xor_c);
    c = xor_gate(a_xor_b_xor_c, a_xor_b_and_b_xor_c);

    i++;
    if (big_endian && (i & 7)==0) i-=16;
  }

  return c;
}


buf128_t oword_simple_shift_left(buf128_t v, int shift)
{
  buf128_t o;
#if defined(INTEL_X64)
  o.value = _mm_slli_epi64(v.value, shift);
#elif defined(__aarch64__)
  struct two64_t { uint64_t hi, lo; };
  two64_t& to = (two64_t&)o;
  two64_t& tv = (two64_t&)v;

  to.lo = tv.lo << shift;
  to.hi = tv.hi << shift;

#else
  o.lo = v.lo << shift;
  o.hi = v.hi << shift;
#endif
  return o;
}

static buf128_t single_encrypt_prepare(buf128_t g1, buf128_t tweak)
{
  return 
    oword_simple_shift_left(g1, 1) ^ 
    tweak;
}

int oword_lsb(buf128_t v)
{
  return int(v.le_half0()) & 1;
}

template<class T> void gc_garble(T& fixed_key, int n_gates, const circuit_def_t::gate_t* gates, buf128_t* garbled, buf128_t* wires, buf128_t delta)
{
  for (int index=0; index<n_gates; index++)
  {
    garbled_circuit_t::wire_t input0 = wires[gates[index].input0];
    garbled_circuit_t::wire_t& output = wires[gates[index].output];

    switch (gates[index].type)
    {
      case circuit_def_t::gate_type_not :
        {
          garbled_circuit_t::gate_t gate = garbled_circuit_t::gate_t(input0, output/*, index*/);
          gate.output = gate.input0 ^ delta;
        }
        break;

      case circuit_def_t::gate_type_xor :
        {
          garbled_circuit_t::wire_t input1 = wires[gates[index].input1];
          garbled_circuit_t::gate_t gate = garbled_circuit_t::gate_t(input0, input1, output/*, index*/);
          gate.output = gate.input0 ^ gate.input1;
        }
        break;

      case circuit_def_t::gate_type_and :
        {
          garbled_circuit_t::wire_t input1 = wires[gates[index].input1];
          garbled_circuit_t::gate_t gate = garbled_circuit_t::gate_t(input0,input1, output/*, index*/);
          buf128_t tweak = buf128_t::make_le(index);
          buf128_t tweak2 = buf128_t::make_le(index + n_gates);

          int lsb0 = oword_lsb(gate.input0);
          int lsb1 = oword_lsb(gate.input1);

          buf128_t x1 = gate.input0;
          buf128_t x2 = gate.input0 ^ delta;
          buf128_t x3 = gate.input1;
          buf128_t x4 = gate.input1 ^ delta;

          x1 = oword_simple_shift_left(x1, 1) ^ tweak;
          x2 = oword_simple_shift_left(x2, 1) ^ tweak;
          x3 = oword_simple_shift_left(x3, 1) ^ tweak2;
          x4 = oword_simple_shift_left(x4, 1) ^ tweak2;

          buf128_t e1,e2,e3,e4;

          fixed_key.encrypt(x1,e1,x2,e2,x3,e3,x4,e4);
          /*e1 = fixed_aes_encrypt(x1);
          e2 = fixed_aes_encrypt(x2);
          e3 = fixed_aes_encrypt(x3);
          e4 = fixed_aes_encrypt(x4);*/

          e1^=x1; e2^=x2; e3^=x3; e4^=x4;

          buf128_t Ke = lsb1 ? e4 : e3;

          buf128_t Tg = e2 ^ e1;
          if (lsb1) Tg ^= delta;

          buf128_t Kg = e1;
          if (lsb0) { Kg ^= Tg; }

          buf128_t Te = e4 ^ e3 ^ gate.input0;

          *garbled++ = Tg;
          *garbled++ = Te;
          gate.output = Kg ^ Ke;
        }
        break;

      default: assert(false);
    }
  }
}

template<class T> void gc_evaluate(T& fixed_key, int n_gates, const circuit_def_t::gate_t* gates, const buf128_t* garbled, buf128_t* wires)
{
  for (int index=0; index<n_gates; index++)
  {
    garbled_circuit_t::wire_t input0 = wires[gates[index].input0];
    garbled_circuit_t::wire_t& output = wires[gates[index].output];

    switch (gates[index].type)
    {
      case circuit_def_t::gate_type_not:
        {
          garbled_circuit_t::gate_t gate = garbled_circuit_t::gate_t(input0, output/*, index*/);
          gate.output = gate.input0;
        }
        break;

      case circuit_def_t::gate_type_xor:
        {
          garbled_circuit_t::wire_t input1 = wires[gates[index].input1];
          garbled_circuit_t::gate_t gate = garbled_circuit_t::gate_t(input0, input1, output/*, index*/);
          gate.output = gate.input0 ^ gate.input1;
        }
        break;

      case circuit_def_t::gate_type_and:
        {
          garbled_circuit_t::wire_t input1 = wires[gates[index].input1];
          garbled_circuit_t::gate_t gate = garbled_circuit_t::gate_t(input0, input1, output/*, index*/);
          buf128_t tweak = buf128_t::make_le(index);
          int lsb0 = oword_lsb(gate.input0);
          int lsb1 = oword_lsb(gate.input1);

          unsigned tweak2_index = index + n_gates;
          buf128_t tweak2 = buf128_t::make_le(tweak2_index);

          buf128_t x1 = single_encrypt_prepare(gate.input0, tweak);
          buf128_t x2 = single_encrypt_prepare(gate.input1, tweak2);
          buf128_t e1,e2;
          fixed_key.encrypt(x1,e1,x2,e2);
          //e1 = fixed_aes_encrypt(x1);
          //e2 = fixed_aes_encrypt(x2);

          e1^=x1; e2^=x2;

          buf128_t Kg = e1;
          if (lsb0) Kg = Kg ^ garbled[0];

          buf128_t Ke = e2;
          if (lsb1) Ke = Ke ^ garbled[1] ^ gate.input0;

          gate.output = Kg ^ Ke;
          garbled+=2;
        }
        break;

      default: assert(false);
    }
  }
}

#if defined(HAS_AESNI_SUPPORT) && !defined(__APPLE__) && !defined(__ANDROID__)

#define GC_AESNI_ASM

extern "C"
{
void gc_garble(int n_gates, const circuit_def_t::gate_t* gates, buf128_t* garbled, buf128_t* wires, crypto::aesni_enc128_t& fixed_aesni_key, buf128_t delta);
void gc_evaluate(int n_gates, const circuit_def_t::gate_t* gates, const buf128_t* garbled, buf128_t* wires, crypto::aesni_enc128_t& fixed_aesni_key, buf128_t delta);
}

#endif

void garbled_circuit_t::garble(int n_gates, const circuit_def_t::gate_t* gates, buf128_t* garbled, buf128_t* wires, buf128_t delta)
{
  bool use_aesni = fixed_aes_key.use_aesni();

  if (use_aesni)
  {
#ifdef GC_AESNI_ASM
    gc_garble(n_gates, gates, garbled, wires, fixed_aes_key.get_aesni(), delta);
#else
    gc_garble(fixed_aes_key.get_aesni(), n_gates, gates, garbled, wires, delta);
#endif
  }
  else
  {
    gc_garble(fixed_aes_key.get_openssl(), n_gates, gates, garbled, wires, delta);
  }
}


void garbled_circuit_t::evaluate(int n_gates, const circuit_def_t::gate_t* gates, const buf128_t* garbled, buf128_t* wires)
{
  bool use_aesni = fixed_aes_key.use_aesni(); 

  if (use_aesni)
  {
#ifdef GC_AESNI_ASM
    gc_evaluate(n_gates, gates, garbled, wires, fixed_aes_key.get_aesni(), 0);
#else
    gc_evaluate(fixed_aes_key.get_aesni(), n_gates, gates, garbled, wires);
#endif
  }
  else
  {
    gc_evaluate(fixed_aes_key.get_openssl(), n_gates, gates, garbled, wires);
  }
}

