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
#include "ub_buf.h"
#include "ub_convert.h"

namespace ub {

buf_t::buf_t() : s(0)
{
  static_assert(sizeof(buf_t)==40, "Invalid buf_t size.");
}
  
buf_t::buf_t(int new_size) : s(new_size) // explicit
{
  if (new_size>short_size) set_long_ptr(new byte_t[new_size]);
}

buf_t::buf_t(const_byte_ptr src, int src_size)
{
  if (src_size<=short_size) assign_short(src, src_size);
  else assign_long(src, src_size);
}

buf_t::buf_t(mem_t mem)
{
  if (mem.size<=short_size) assign_short(mem.data, mem.size);
  else assign_long(mem.data, mem.size);
}

buf_t::operator buf128_t() const
{
  assert(s==sizeof(buf128_t));
  return buf128_t::load(m);
}

buf_t& buf_t::operator= (buf128_t src)
{
  if (s>short_size) 
  {
    byte_ptr old_long_ptr = get_long_ptr();
    ub::secure_bzero(old_long_ptr, s);
    delete[] old_long_ptr;
  }

  s = sizeof(buf128_t);
  src.save(m);
  return *this;
}

buf_t::buf_t(buf128_t src) : s(sizeof(buf128_t))
{
  src.save(m);
}

buf_t::operator buf256_t() const
{
  assert(s==sizeof(buf256_t));
  return buf256_t::load(m);
}


buf_t& buf_t::operator= (buf256_t src)
{
  if (s>short_size) 
  {
    byte_ptr old_long_ptr = get_long_ptr();
    ub::secure_bzero(old_long_ptr, s);
    delete[] old_long_ptr;
  }

  s = sizeof(buf256_t);
  src.save(m);
  return *this;
}

buf_t::buf_t(buf256_t src) : s(sizeof(buf256_t))
{
  src.save(m);
}

void buf_t::free() 
{
  int size = s;
  byte_ptr ptr = data();
  ub::secure_bzero(ptr, s);
  if (size>short_size) delete[] ptr; 
  s = 0;
}

buf_t::~buf_t() 
{
  free();
}

byte_ptr buf_t::data() const 
{
  return (s<=short_size) ? byte_ptr(m) : get_long_ptr();
}

int buf_t::size() const
{
  return s;
}

bool buf_t::empty() const 
{
  return s==0;
}

buf_t& buf_t::operator = (mem_t src)
{
  if (s!=src.size || data()!=src.data)
  {
    if (src.size<=short_size) assign_short(src.data, src.size);
    else assign_long(src.data, src.size);
  }
  return *this;
}

buf_t::buf_t(const buf_t& src)
{
  if (src.s<=short_size) assign_short(src);
  else assign_long(src.data(), src.s);
}

buf_t::buf_t(buf_t&& src) 
{
  if (src.s<=short_size) assign_short(src);
  else 
  {
    assign_long_ptr(src.get_long_ptr(), src.s);
    src.s = 0;
  }
}

buf_t& buf_t::operator = (const buf_t& src)
{
  if (this != &src)
  {
    free();

    if (src.s <= short_size) assign_short(src);
    else assign_long(src.data(), src.s);
  }

  return *this;
}

buf_t& buf_t::operator = (buf_t&& src)
{
  if (&src!=this)
  {
    free();

    if (src.s<=short_size) assign_short(src);
    else 
    {
      assign_long_ptr(src.get_long_ptr(), src.s);
      src.s = 0;
    }
  }
  return *this;
}

byte_ptr buf_t::resize_save_short_to_short(int new_size)
{
  s = new_size;
  return m;
}

byte_ptr buf_t::resize_save_short_to_long(int new_size)
{
  byte_ptr new_ptr = new byte_t[new_size];
  memmove(new_ptr, m, s);
  assign_long_ptr(new_ptr, new_size);
  return new_ptr;
}

byte_ptr buf_t::resize_save_long_to_short(int new_size)
{
  byte_ptr old_ptr = get_long_ptr();
  memmove(m, old_ptr, new_size);
  ub::secure_bzero(old_ptr, s);
  delete[] old_ptr;
  s = new_size;
  return m;
}

byte_ptr buf_t::resize_save_long_to_long(int new_size)
{
  byte_ptr old_ptr = get_long_ptr();
  byte_ptr new_ptr = new byte_t[new_size];
    
  int copy_size = s < new_size ? s : new_size;
  memmove(new_ptr, old_ptr, copy_size);

  ub::secure_bzero(old_ptr, s);
  delete[] old_ptr;

  assign_long_ptr(new_ptr, new_size);
  return new_ptr;
}

byte_ptr buf_t::resize(int new_size, bool save)
{
  if (!save) 
  {
    free();
    s = new_size;
    if (new_size<=short_size) return m;
    byte_ptr new_ptr = new byte_t[new_size];
    set_long_ptr(new_ptr);
    return new_ptr;
  }

  if (s<=short_size)
  {
    if (new_size<=short_size) return resize_save_short_to_short(new_size);
    return resize_save_short_to_long(new_size);
  }

  if (new_size<=short_size) return resize_save_long_to_short(new_size);
  return resize_save_long_to_long(new_size);
}

void buf_t::bzero()
{
  ub::bzero(data(), s);
}

void buf_t::secure_bzero()
{
  ub::secure_bzero(data(), s);
}

bool buf_t::operator == (const buf_t& src) const 
{ 
  return 
    s==src.s && 
    0==memcmp(data(), src.data(), s); 
}

bool buf_t::operator != (const buf_t& src) const 
{ 
  return 
    s!=src.s ||
    0!=memcmp(data(), src.data(), s); 
}

buf_t::operator mem_t () const
{
  return mem_t(data(), s);
}

uint8_t buf_t::operator [] (int index) const { return data()[index]; }
uint8_t& buf_t::operator [] (int index) { return data()[index]; }

buf_t operator ^ (mem_t src1, mem_t src2)
{
  assert(src1.size==src2.size);
  buf_t out(src1.size);

  byte_ptr dst = out.data();
  for (int i=0; i<src2.size; i++) dst[i] = src1.data[i] ^ src2.data[i];

  return out;
}

buf_t& buf_t::operator ^= (mem_t src2)
{
  assert(src2.size==s);

  byte_ptr dst = data();
  for (int i=0; i<src2.size; i++) dst[i] ^= src2.data[i];
  return *this;
}

buf_t operator + (mem_t src1, mem_t src2)
{
  buf_t out(src1.size + src2.size);
  memmove(out.data(), src1.data, src1.size);
  memmove(out.data() + src1.size, src2.data, src2.size);
  return out;
}

buf_t& buf_t::operator += (mem_t src)
{
  int old_size = s;
  byte_ptr new_ptr = resize(old_size + src.size, true);
  memmove(new_ptr + old_size, src.data, src.size);
  return *this;
}

void buf_t::reverse() 
{ 
  mem_t(*this).reverse(); 
}

std::string buf_t::to_string() const
{
  return std::string(const_char_ptr(data()), s);
}


byte_ptr buf_t::get_long_ptr() const
{
#ifdef BUF_PTR_64BIT
  return ((byte_ptr*)m)[0];
#else
  return ((byte_ptr*)m)[0];
#endif
  //return p;
}

void buf_t::set_long_ptr(byte_ptr ptr)
{
#ifdef BUF_PTR_64BIT
  ((byte_ptr*)m)[0] = ptr;
#else
  ((byte_ptr*)m)[0] = ptr;
#endif
  //p = ptr;
}

void buf_t::assign_short(const_byte_ptr src, int src_size)
{
  for (int i=0; i<src_size; i++) m[i] = src[i];
  s = src_size;
}

void buf_t::assign_short(const buf_t& src)
{
#ifdef _WIN64
  __movsq((uint64_t*)m, (uint64_t*)src.m, 5);
#else
  for (int i=0; i<5; i++) ((uint64_t*)m)[i] = ((uint64_t*)src.m)[i];
#endif
}

void buf_t::assign_long_ptr(byte_ptr ptr, int size)
{
  set_long_ptr(ptr);
  s = size;
}  

void buf_t::assign_long(const_byte_ptr ptr, int size)
{
  byte_ptr new_ptr = new byte_t[size];
  memmove(new_ptr, ptr, size);
  assign_long_ptr(new_ptr, size);
}  

void buf_t::convert(converter_t& converter)
{
  uint32_t value_size = size();
  converter.convert_len(value_size);

  if (converter.is_write())
  {
    if (!converter.is_calc_size()) memmove(converter.current(), data(), value_size);
  }
  else
  {
    if (converter.is_error() || !converter.at_least(value_size)) { converter.set_error(); return; }
    *this = mem_t(converter.current(), value_size);
  }
  converter.forward(value_size);
}

void buf_t::convert_long(converter_t& converter)
{
  int value_size = size();
  converter.convert(value_size);

  if (converter.is_write())
  {
    if (!converter.is_calc_size()) memmove(converter.current(), data(), value_size);
  }
  else
  {
    if (value_size<0) { converter.set_error(); return; }
    if (converter.is_error() || !converter.at_least(value_size)) { converter.set_error(); return; }
    *this = mem_t(converter.current(), value_size);
  }
  converter.forward(value_size);
}


buf_t make_buf(byte_t src)  { buf_t out(1);  out[0] = src;  return out; }
buf_t make_be(short src)    { buf_t out(2);  be_set_2(out.data(), src);  return out; }
buf_t make_le(short src)    { buf_t out(2);  le_set_2(out.data(), src);  return out; }
buf_t make_be(int src)      { buf_t out(4);  be_set_4(out.data(), src);  return out; }
buf_t make_le(int src)      { buf_t out(4);  le_set_4(out.data(), src);  return out; }
buf_t make_be(uint64_t src) { buf_t out(8);  be_set_8(out.data(), src);  return out; }
buf_t make_le(uint64_t src) { buf_t out(8);  le_set_8(out.data(), src);  return out; }

} // namespace ub
