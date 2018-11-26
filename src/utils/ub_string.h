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
#include "ub_common.h"

namespace ub {


class encoding_t
{
public:
  encoding_t() {}
  virtual ~encoding_t() {}
  
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const =0;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const =0;
  virtual int get_codes_count() const =0;
  virtual int symbol_to_code(uint32_t s) const =0;
  virtual uint32_t code_to_symbol(int code) const =0;


  std::string convert(const mem_t src) const ;
  int convert(char_ptr dst, const mem_t src) const ;

  buf_t convert(const_char_ptr src) const;
  buf_t convert(const_char_ptr src, int size) const;
  buf_t convert(const std::string& str) const { return convert(str.c_str(), int(str.length())); }
  int convert(byte_ptr dst, const_char_ptr src) const;
  int convert(byte_ptr dst, const_char_ptr src, int size) const;
  int convert(byte_ptr dst, const std::string& src) const { return convert(dst, src.c_str(), int(src.length())); }
};

class ascii_t : public encoding_t
{
public:
  ascii_t() {}
  ~ascii_t() {}
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const;
  virtual int get_codes_count() const;
  virtual int symbol_to_code(uint32_t s) const;
  virtual uint32_t code_to_symbol(int code) const;
};

class unicode_t : public encoding_t
{
public:
  unicode_t() {}
  ~unicode_t() {}
  virtual int get_codes_count() const;
  virtual int symbol_to_code(uint32_t s) const;
  virtual uint32_t code_to_symbol(int code) const;
};

class utf8_t : public unicode_t
{
public:
  utf8_t() {}
  ~utf8_t() {}
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const;
  int count(const std::string& str) const;
  uint32_t get_symbol(const std::string& str, int index) const;
};

class utf16le_t : public unicode_t
{
public:
  utf16le_t() {}
  ~utf16le_t() {}
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const;
};

class utf16be_t : public unicode_t
{
public:
  utf16be_t() {}
  ~utf16be_t() {}
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const;
};

class ucs2le_t : public utf16le_t
{
public:
  ucs2le_t() {}
  ~ucs2le_t() {}
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const;
  virtual int get_codes_count() const;
  virtual int symbol_to_code(uint32_t s) const;
  virtual uint32_t code_to_symbol(int code) const;
};

class ucs2be_t : public utf16be_t
{
public:
  ucs2be_t() {}
  ~ucs2be_t() {}
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const;
  virtual int get_codes_count() const;
  virtual int symbol_to_code(uint32_t s) const;
  virtual uint32_t code_to_symbol(int code) const;
};

class utf32le_t : public unicode_t
{
public:
  utf32le_t() {}
  ~utf32le_t() {}
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const;
};

class utf32be_t : public unicode_t
{
public:
  utf32be_t() {}
  ~utf32be_t() {}
  virtual int get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const;
  virtual int put_symbol(byte_ptr dst, uint32_t src) const;
};

extern const ascii_t   ascii;
extern const utf8_t    utf8;
extern const utf16le_t utf16le;
extern const utf16be_t utf16be;
extern const utf32le_t utf32le;
extern const utf32be_t utf32be;
extern const ucs2le_t  ucs2le;
extern const ucs2be_t  ucs2be;

} //namespace ub

#ifndef _WIN32
#define sprintf_s sprintf
#endif


struct strext
{

  static char_ptr buffer(std::string& s) { return &s[0]; }
  static mem_t mem(const std::string& s) { return mem_t((const_byte_ptr)s.c_str(), (int)s.length()); }

  static int compare_nocase(const_char_ptr str1, const std::string& str2);
  static int compare_nocase(const std::string& str1, const_char_ptr str2);
  static int compare_nocase(const std::string& str1, const std::string& str2);
  static bool equal_nocase(const_char_ptr str1, const std::string& str2)        { return 0==compare_nocase(str1, str2); }
  static bool equal_nocase(const std::string& str1, const_char_ptr str2)        { return 0==compare_nocase(str1, str2); }
  static bool equal_nocase(const std::string& str1, const std::string& str2)    { return 0==compare_nocase(str1, str2); }

  static std::string from_char_ptr(const_char_ptr ptr);

  static std::string to_upper(const std::string& str);
  static std::string to_lower(const std::string& str);
  static void make_upper(std::string& str);
  static void make_lower(std::string& str);
  
  static int find_nocase(const std::string& str, const std::string& what) { return find_nocase(str, what.c_str()); }
  static int find_nocase(const std::string& str, const_char_ptr what);
  static int find_nocase(const std::string& str, char c);
  static int rfind_nocase(const std::string& str, char c);

  static void trim_left(std::string& str);
  static void trim_right(std::string& str);
  static void trim(std::string& str) { trim_left(str); trim_right(str); }

  static std::string left(const std::string& str, int count) { return str.substr(0, count); }
  static std::string right(const std::string& str, int count) { return str.substr(str.length()-count, count); }

  static bool starts_width(const std::string& str, const std::string& start);
  static bool ends_width(const std::string& str, const std::string& end);

  static std::vector<std::string> tokenize(const std::string& str, const std::string& delim = " ");


  static std::string format_arg(const_char_ptr f, va_list arg);
#ifdef _WIN32  
  static std::string __cdecl format(const_char_ptr f, ...);
#else
  static std::string format(const_char_ptr f, ...);
#endif  

  static std::string itoa(int value);
  static int atoi(const std::string& str) { return (int)::strtol(str.c_str(), 0, 10); }
  static double atod(const std::string& str) { return (double)::strtod(str.c_str(), 0); }
  static std::string to_hex(mem_t hex);
  static std::string to_hex(uint8_t src);
  static std::string to_hex(uint16_t src);
  static std::string to_hex(uint32_t src);
  static std::string to_hex(uint64_t src);
  static bool from_hex(buf_t& dst, const std::string& src);
  static bool from_hex(uint8_t& dst, const std::string& src);
  static bool from_hex(uint16_t& dst, const std::string& src);
  static bool from_hex(uint32_t& dst, const std::string& src);
  static bool from_hex(uint64_t& dst, const std::string& src);

  static int scan_hex_byte(const_char_ptr str);
  static void print_hex_byte(char_ptr str, uint8_t value);
};


