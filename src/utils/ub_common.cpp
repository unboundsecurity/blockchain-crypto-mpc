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
#include "ub_common.h"
#include "ub_convert.h"

#ifdef _WIN32
#pragma comment(lib, "shlwapi.lib")
#endif


namespace ub {



void mem_t::reverse()
{
  int l = 0; int r = size - 1;
  while (l<r) { uint8_t t = data[l]; data[l] = data[r]; data[r] = t; l++; r--; }
}

bool mem_t::equal(mem_t m1, mem_t m2)
{
  return m1.size == m2.size && 0 == memcmp(m1.data, m2.data, m1.size);
}

bool mem_t::operator== (const mem_t& m2) const { return mem_t::equal(*this, m2); }
bool mem_t::operator!= (const mem_t& m2) const { return !mem_t::equal(*this, m2); }

bool mem_t::operator== (const buf_t& m2) const { return mem_t::equal(*this, mem_t(m2)); }
bool mem_t::operator!= (const buf_t& m2) const { return !mem_t::equal(*this, mem_t(m2)); }

void mem_t::convert(converter_t& converter)
{
  assert(converter.is_write());
  short value_size = short(size);
  converter.convert(value_size);
  if (!converter.is_calc_size()) memmove(converter.current(), data, value_size);
  converter.forward(value_size);
}


// ------------------------- bits_t ---------------------
static int bits_to_limbs(int bits) { return (bits+63) / 64; }

bits_t::bits_t() : data(nullptr), bits(0)
{
}
  
bits_t::bits_t(bits_t&& src) // move constructor
{
  data = src.data;
  bits = src.bits;
  src.data = nullptr;
  src.bits = 0;
}

bits_t& bits_t::operator=(bits_t&& src) // move assignment
{
  if (&src!=this)
  {
    free();
    data = src.data;
    bits = src.bits;
    src.data = nullptr;
    src.bits = 0;
  }
  return *this;
}

void bits_t::free()
{
  if (bits) 
  {
    int n = bits_to_limbs(bits);
    secure_bzero((byte_ptr)data, n*sizeof(uint64_t));
    delete[] data;
  }
  data = nullptr;
  bits = 0;
}

void bits_t::copy_from(const bits_t& src)
{
  if (&src==this) return;

  resize(src.bits);

  int n = bits_to_limbs(bits);
  memmove(data, src.data, n*sizeof(uint64_t));
}


bits_t::bits_t(const bits_t& src) : data(nullptr), bits(0) // copy constructor
{
  copy_from(src);
}

bits_t::bits_t(int count) : data(nullptr), bits(0) 
{
  if (!count) return;
  bits = count;
  int n = bits_to_limbs(bits);
  data = new uint64_t[n];
  memset(data, 0, n*sizeof(uint64_t));
}


bits_t& bits_t::operator=(const bits_t& src) // copy assignment
{
  copy_from(src);
  return *this;
}

void bits_t::bzero() 
{ 
  ub::bzero(byte_ptr(data), bits_to_limbs(bits)*sizeof(uint64_t)); 
}

void bits_t::convert(converter_t& converter)
{
  int value_size;
  if (converter.is_write())
  {
    value_size = save(converter.is_calc_size() ? nullptr : converter.current());
  }
  else
  {
    value_size = load(mem_t(converter.current(), converter.get_size()-converter.get_offset()));
    if (value_size<=0) { converter.set_error(); return; }
  }
  converter.forward(value_size);
}


void bits_t::resize(int count, bool save)
{
  if (count==0) { free(); return; }

  int n_old = bits_to_limbs(bits);
  int n_new = bits_to_limbs(count);
  if (n_old==n_new) return;

  uint64_t* old_data = data;
  data = new uint64_t[n_new];
  bits = count;

  if (save) 
  {
    int n_copy = std::min(n_old, n_new);
    if (n_copy) memmove(data, old_data, n_copy*sizeof(uint64_t));
  }

  if (n_old)
  {
    secure_bzero((byte_ptr)old_data, n_old*sizeof(uint64_t));
    delete[] old_data;
  }
}

bits_t::ref_t::ref_t(uint64_t* ptr, int index) : data(ptr[index/64]), offset(index & 63)
{
}

bool bits_t::get(int index) const
{
  return ref_t(data, index).get();
}
  
void bits_t::set(int index, bool value)
{
  ref_t(data, index).set(value);
}

void bits_t::append(bool value)
{
  resize(bits+1, true);
  set(bits-1, value);
}

void bits_t::ref_t::set(bool value)
{
  uint64_t mask       = uint64_t(1) << offset;
  uint64_t mask_value = uint64_t(value ? 1 : 0) << offset;
  data = (data & ~mask) | mask_value;
}

bool bits_t::ref_t::get() const
{
  return 0 != ((data >> offset) & 1);
}

bits_t::ref_t bits_t::operator[] (int index)
{
  return ref_t(data, index);
}

int bits_t::save(byte_ptr out) const
{
  int n = bits_to_limbs(bits);
  if (out)
  {
    be_set_4(out, bits);
    out+=4;
    for (int i=0; i<n; i++, out+=sizeof(uint64_t)) be_set_8(out, data[i]);
  }

  return sizeof(int)+n*sizeof(uint64_t);
}
  
int bits_t::load(mem_t in)
{
  if (in.size<sizeof(int)) return 0;

  int bits_count = be_get_4(in.data);
  int n = bits_to_limbs(bits_count);
  int size = sizeof(int) + n*sizeof(uint64_t);
  if (in.size<size) return 0;

  resize(bits_count);
  const_byte_ptr ptr = in.data+sizeof(int);
  for (int i=0; i<n; i++, ptr+=sizeof(uint64_t)) data[i] = be_get_8(ptr);

  return size;
}

bool bits_t::equ(const bits_t& src1, const bits_t& src2) 
{
  if (src1.bits!=src2.bits) return false;

  int n = src1.bits / 64;
  if (n>0)
  {
    if (0!=memcmp(src1.data, src2.data, n*sizeof(uint64_t))) return false;
  }

  for (int i=n*64; i<src1.bits; i++)
  {
    if (src1[i]!=src2[i]) return false;
  }

  return true;
}

uint64_t read_timer_ms()
{
#ifdef _WIN32
  static LARGE_INTEGER freq = { 0 };
  if (!freq.QuadPart) ::QueryPerformanceFrequency(&freq);
  LARGE_INTEGER time;
  ::QueryPerformanceCounter(&time);
  return time.QuadPart * 1000 / freq.QuadPart;
#elif defined(__APPLE__)
  static mach_timebase_info_data_t freq = { 0 };
  if (freq.denom == 0) mach_timebase_info(&freq);
  return int64_t(mach_absolute_time()) * freq.numer / (freq.denom * 1000000);
#else
  struct timespec tp = { 0 };
  clock_gettime(CLOCK_MONOTONIC, &tp);
  return int64_t(tp.tv_sec) * 1000 + tp.tv_nsec / 1000000;
#endif
}

} // namespace ub
