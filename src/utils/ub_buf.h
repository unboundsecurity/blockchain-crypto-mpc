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
#include "ub_common_def.h"

#define LOGMEM(v) dylog_t::log_bytes(dylog_ctx, #v, (const void*)(v).data, (v).size)
#define LOGBUFFER(v) dylog_t::log_bytes(dylog_ctx, #v, (const void*)(v).data(), (v).size())

namespace ub {

void memmove_reverse(byte_ptr dst, const_byte_ptr src, int size);

#ifdef bzero
#undef bzero
#endif
inline void bzero(byte_ptr pointer, int size) { memset(pointer, 0, size); }

#ifdef _WIN32
inline void secure_bzero(byte_ptr pointer, int size) { SecureZeroMemory(pointer, size); }
#else
inline void secure_bzero(byte_ptr pointer, int size) { volatile unsigned char* p = pointer; while (size--) *p++ = 0; }
#endif

template <size_t size> void bzero(uint8_t (&buffer)[size]) { bzero(buffer, size); }
template <size_t size> void bzero(char (&buffer)[size]) { bzero(byte_ptr(buffer), size); }
template <size_t size> void secure_bzero(uint8_t (&buffer)[size]) { secure_bzero(buffer, size); }
template <size_t size> void secure_bzero(char (&buffer)[size]) { secure_bzero(byte_ptr(buffer), size); }

class buf_t;
class converter_t;

struct mem_t
{
  byte_ptr data;
  int size;
  mem_t() : data(0), size(0) {}
  mem_t(const_byte_ptr the_data, int the_size) : data(byte_ptr(the_data)), size(the_size) {}

  void bzero() { ub::bzero(data, size); }
  void secure_bzero() { ub::secure_bzero(data, size); }
  void reverse();
  
  bool operator== (const mem_t& b2) const;
  bool operator!= (const mem_t& b2) const;
  bool operator== (const buf_t& b2) const;
  bool operator!= (const buf_t& b2) const;
  uint8_t operator [] (int index) const { return data[index]; }
  uint8_t& operator [] (int index) { return data[index]; }
  
  mem_t range(int offset, int size) const { return mem_t(data+offset, size); }
  static mem_t from_string(const std::string& str) { return mem_t(const_byte_ptr(str.c_str()), int(str.length())); }

  void convert(converter_t& converter); // write only

private:
  static bool equal(mem_t m1, mem_t m2);
};

} // namespace ub

using ub::mem_t;


#include "ub_buf128.h"
#include "ub_buf256.h"

namespace ub {

class buf_t
{
public:

  buf_t(); 
  explicit buf_t(int new_size);
  buf_t(const_byte_ptr src, int src_size);
  buf_t(mem_t mem);
  buf_t(const buf_t& src);
  buf_t(buf_t&& src);
  buf_t(buf128_t src);
  buf_t(buf256_t src);

  void free();
  ~buf_t();

  byte_ptr data() const;
  int size() const;
  bool empty() const;
//  void assign(const_byte_ptr src, int src_size);
//  void assign(mem_t mem);
  byte_ptr resize(int new_size, bool save=false);
  void bzero();
  void secure_bzero();
  void reverse();

  buf_t& operator = (const buf_t& src);
  buf_t& operator = (buf_t&& src);
  buf_t& operator = (mem_t src);
  buf_t& operator = (buf128_t src);
  buf_t& operator = (buf256_t src);
  buf_t& operator += (mem_t src);

  bool operator == (const buf_t& src) const;
  bool operator != (const buf_t& src) const;

  uint8_t operator [] (int index) const;
  uint8_t& operator [] (int index);

  operator mem_t () const;

#ifdef _WIN32
  explicit 
#endif
  operator buf128_t () const;

#ifdef _WIN32
  explicit 
#endif
  operator buf256_t () const;

  buf_t& operator ^= (mem_t src2);
  std::string to_string() const;

  void convert(converter_t& converter);
  void convert_long(converter_t& converter);
  //void convert_fix(converter_t& converter, int fix_size);

private:

  enum { short_size=36 };
  
#ifdef _DEBUG
  union {
    struct { byte_t m[short_size]; int s; };
    byte_ptr p; 
  };
#else
  byte_t m[short_size];
  int s;
#endif

  byte_ptr get_long_ptr() const;
  void set_long_ptr(byte_ptr ptr);
  void assign_short(const_byte_ptr src, int src_size);
  void assign_short(const buf_t& src);
  void assign_long_ptr(byte_ptr ptr, int size);
  void assign_long(const_byte_ptr ptr, int size);
  
  byte_ptr resize_save_short_to_short(int new_size);
  byte_ptr resize_save_short_to_long(int new_size);
  byte_ptr resize_save_long_to_short(int new_size);
  byte_ptr resize_save_long_to_long(int new_size);
};


buf_t operator + (mem_t src1, mem_t src2);
buf_t operator ^ (mem_t src1, mem_t src2);


buf_t make_buf(byte_t src);
buf_t make_be(short src);
buf_t make_le(short src);
buf_t make_be(int src);
buf_t make_le(int src);
buf_t make_be(uint64_t src);
buf_t make_le(uint64_t src);


class bits_t
{
public:
  bits_t();
  bits_t(int count);
  
  bits_t(const bits_t& src); // copy constructor
  bits_t(bits_t&& src); // move constructor
  bits_t& operator=(const bits_t& src); // copy assignment
  bits_t& operator=(bits_t&& src); // move assignment

  ~bits_t() { free(); }

  int count() const { return bits; }
  bool empty() const { return bits==0; }

  void free();
  void resize(int count, bool save=false);
  void bzero();

  void convert(converter_t& converter);

  bool operator == (const bits_t& src2) const { return equ(*this, src2); }
  bool operator != (const bits_t& src2) const { return !equ(*this, src2); }

private:
  class ref_t
  {
    friend class bits_t;

  public:
    bool operator=(bool value) { set(value); return value; }
    operator bool() const { return get(); }
    ref_t& operator=(const ref_t& src) { set(src.get()); return *this; }

  private:
    bool get() const;
    void set(bool value);

    ref_t(uint64_t* ptr, int index);
    uint64_t& data;
    int offset;
  };

public:
  bool operator[] (int index) const { return get(index); }
  ref_t operator[] (int index);

  bool get(int index) const;
  void set(int index, bool value);
  void append(bool bit);

  static bool equ(const bits_t& src1, const bits_t& src2);

  int save(byte_ptr out) const;
  int load(mem_t in);

  uint64_t* get_data_buffer() { return data; }

private:

  void copy_from(const bits_t& src);

  uint64_t* data;
  int bits;
};

} //namespace ub

using ub::buf_t;
