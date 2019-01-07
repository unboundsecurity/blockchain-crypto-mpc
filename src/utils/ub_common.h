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
#include "ub_error.h"

namespace ub  {

inline int bits_to_bytes(int bits) { return (bits+7)/8; }
inline int bytes_to_bits(int bytes) { return bytes*8; }

int atomic_add(volatile int& value, int count);
int atomic_sub(volatile int& value, int count);
int atomic_inc(volatile int& value);
int64_t atomic_inc(volatile int64_t& value);
int atomic_dec(volatile int& value);
int64_t atomic_dec(volatile int64_t& value);

bool atomic_compare_exhange(volatile int& value, int old_value, int new_value);
bool atomic_compare_exhange(volatile int64_t& value, int64_t old_value, int64_t new_value);
bool atomic_compare_exhange_ptr(volatile void_ptr& value, void_ptr old_value, void_ptr new_value);

typedef volatile int once_t;
enum { once_init=0, once_busy=1, once_ready=2 };
bool once_begin(once_t& once);
void once_end(once_t& once);

inline uint16_t be_get_2(const_byte_ptr src) { return (uint16_t(src[0]) << 8) | src[1]; }
inline uint16_t le_get_2(const_byte_ptr src) { return (uint16_t(src[1]) << 8) | src[0]; }
inline uint32_t be_get_4(const_byte_ptr src) { return (uint32_t(be_get_2(src+0)) << 16) | be_get_2(src+2); }
inline uint32_t le_get_4(const_byte_ptr src) { return (uint32_t(le_get_2(src+2)) << 16) | le_get_2(src+0); }
inline uint64_t be_get_8(const_byte_ptr src) { return (uint64_t(be_get_4(src+0)) << 32) | be_get_4(src+4); }
inline uint64_t le_get_8(const_byte_ptr src) { return (uint64_t(le_get_4(src+4)) << 32) | le_get_4(src+0); }

inline void be_set_2(byte_ptr dst, uint16_t value) { dst[0] = uint8_t(value>>8); dst[1] = uint8_t(value);    }
inline void le_set_2(byte_ptr dst, uint16_t value) { dst[0] = uint8_t(value);    dst[1] = uint8_t(value>>8); }
inline void be_set_4(byte_ptr dst, uint32_t value) { be_set_2(dst, uint16_t(value>>16));  be_set_2(dst+2, uint16_t(value));     }
inline void le_set_4(byte_ptr dst, uint32_t value) { le_set_2(dst, uint16_t(value));      le_set_2(dst+2, uint16_t(value>>16)); }
inline void be_set_8(byte_ptr dst, uint64_t value) { be_set_4(dst, uint32_t(value>>32));  be_set_4(dst+4, uint32_t(value));     }
inline void le_set_8(byte_ptr dst, uint64_t value) { le_set_4(dst, uint32_t(value));      le_set_4(dst+4, uint32_t(value>>32)); }

class ref_counter_t
{
public:
  ref_counter_t() : ref_count(1) {}
  virtual ~ref_counter_t() {}
  void inc_ref() { atomic_inc(ref_count); }
  void dec_ref() { if (atomic_dec(ref_count)==0) delete this; }

protected:
  volatile int ref_count;
};

template <typename T> class scoped_ptr_t
{
public:
  typedef T* ptr_type;

  scoped_ptr_t(T* _ptr=0) : ptr(_ptr) {}
  ~scoped_ptr_t() { free(); }
  void attach(T* _ptr) { ptr=_ptr; }
  T* detach() { T* old=ptr; ptr=0; return old; }
  void free() { if (ptr) free(ptr); ptr=0; }
  operator T* () const { return ptr; }
  T* operator->() const { return ptr; }
  operator bool () const { return ptr!=0; }
  bool operator !() const { return ptr==0; }
  T* pointer() const { return ptr; }

protected:
  T* ptr;
  static void free(T* ptr);
};

uint64_t read_timer_ms();

} // namespace ub


#include "ub_buf.h"
#include "ub_string.h"
#include "ub_thread.h"


