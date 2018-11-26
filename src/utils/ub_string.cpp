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

#ifdef _WIN32
#define strcasecmp _stricmp
#define strcasestr StrStrIA
#pragma comment(lib, "shlwapi.lib")
#endif

int strext::compare_nocase(const_char_ptr str1, const std::string& str2)
{
  if (!str1) str1 = "";
  return strcasecmp(str1, str2.c_str());
}

int strext::compare_nocase(const std::string& str1, const_char_ptr str2)
{
  if (!str2) str2 = "";
  return strcasecmp(str1.c_str(), str2);
}

int strext::compare_nocase(const std::string& str1, const std::string& str2)
{
  return strcasecmp(str1.c_str(), str2.c_str());
}

std::string strext::from_char_ptr(const_char_ptr ptr)
{
  if (!ptr) return "";
  return ptr;
}

void strext::make_upper(std::string& str) { std::transform(str.begin(), str.end(), str.begin(), ::toupper); }
void strext::make_lower(std::string& str) { std::transform(str.begin(), str.end(), str.begin(), ::tolower); }

std::string strext::to_upper(const std::string& str)
{
  std::string dst = str;
  make_upper(dst);
  return dst;
}

std::string strext::to_lower(const std::string& str)
{
  std::string dst = str;
  make_lower(dst);
  return dst;
}

int strext::scan_hex_byte(const_char_ptr str)
{
  unsigned result = 0;
  for (int i=0; i<2; i++)
  {
    unsigned x;
    char c = *str++;
    if (c>='0' && c<='9') x = c-'0';
    else if (c>='a' && c<='f') x = c-'a'+10;
    else if (c>='A' && c<='F') x = c-'A'+10;
    else return -1;
    result <<= 4;
    result |= x;
  }
  return result;
}

void strext::print_hex_byte(char_ptr str, uint8_t value)
{
  const char hex[] = "0123456789abcdef";
  *str++ = hex[value >> 4];
  *str++ = hex[value & 15];
}

std::string strext::to_hex(mem_t mem)
{
  std::string out(mem.size*2, char(0));
  char_ptr s = buffer(out);
  for (int i=0; i<mem.size; i++, s+=2) print_hex_byte(s, mem.data[i]);
  return out;
}

static std::string print_hex(uint64_t src, int dst_size)
{
  std::string out(dst_size*2, char(0));
  char_ptr s = strext::buffer(out)+dst_size*2-2;
  for (int i=0; i<dst_size; i++, s-=2) strext::print_hex_byte(s, uint8_t(src >> (i*8)));
  return out;
}

std::string strext::to_hex(uint8_t src)
{
  return print_hex(src, 1);
}

std::string strext::to_hex(uint16_t src)
{
  return print_hex(src, 2);
}

std::string strext::to_hex(uint32_t src)
{
  return print_hex(src, 4);
}

std::string strext::to_hex(uint64_t src)
{
  return print_hex(src, 8);
}



bool strext::from_hex(buf_t& dst, const std::string& src)
{
  int length = (int)src.length();
  if (length & 1) return false;
  int dst_size = length/2;
  const_char_ptr hex = src.c_str();
  byte_ptr d = dst.resize(dst_size);

  for (int i=0; i<dst_size; i++, hex+=2)
  {
    int v = strext::scan_hex_byte(hex);
    if (v<0) return false;
    *d++ = v;    
  }
  return true;
}

static bool scan_hex_bytes(uint64_t& dst, const std::string& src, int dst_size)
{
  int length = (int)src.length();
  if (length < dst_size * 2) return false;
  const_char_ptr hex = src.c_str();
  uint64_t result = 0;
  for (int i = 0; i < dst_size; i++, hex+=2)
  {
    int v = strext::scan_hex_byte(hex);
    if (v<0) return false;
    result = (result << 8) | v;
  }
  dst = result;
  return true;
}

bool strext::from_hex(uint8_t& dst, const std::string& src)
{
  uint64_t v;
  if (!scan_hex_bytes(v, src, 1)) return false;
  dst = uint8_t(v);
  return true;
}

bool strext::from_hex(uint16_t& dst, const std::string& src)
{
  uint64_t v;
  if (!scan_hex_bytes(v, src, 2)) return false;
  dst = uint16_t(v);
  return true;
}

bool strext::from_hex(uint32_t& dst, const std::string& src)
{
  uint64_t v;
  if (!scan_hex_bytes(v, src, 4)) return false;
  dst = uint32_t(v);
  return true;
}

bool strext::from_hex(uint64_t& dst, const std::string& src)
{
  return scan_hex_bytes(dst, src, 8);
}

int strext::find_nocase (const std::string& str, const_char_ptr what)
{
  const_char_ptr s = str.c_str();
  const_char_ptr w = strcasestr(str.c_str(), what);
  if (!w) return -1;
  return (int)(w-s);
}

int strext::find_nocase(const std::string& str, char what)
{
#ifdef _WIN32
  const_char_ptr s = str.c_str();
  const_char_ptr w = StrChrIA(s, what);
  if (!s) return -1;
  return (int)(w-s);
#else
  char temp[] = {what,0};
  return find_nocase(str, temp);
#endif
}

int strext::rfind_nocase(const std::string& str, char what) 
{
#ifdef _WIN32
  const_char_ptr s = str.c_str();
  const_char_ptr w = StrRChrIA(s, s+str.length(), what);
  if (!s) return -1;
  return (int)(w-s);
#else
  int u = (int)str.rfind(toupper(what));
  int l = (int)str.rfind(toupper(what));
  return std::max(u,l);
#endif
}

void strext::trim_left(std::string& str)
{
  int n=0, len=int(str.length());
  const_char_ptr s = str.c_str();
  while (n<len && s[n]<=' ') n++;
  if (n>0) str.assign(s+n, len-n);
}

void strext::trim_right(std::string& str)
{
  int len=int(str.length()); int n=len;
  const_char_ptr s = str.c_str();
  while (n>0 && s[n-1]<=' ') n--;
  if (n<len) str.resize(n);
}


std::string strext::itoa(int value)
{
  char buffer[128] = "";
  sprintf_s(buffer,"%d",value);
  return buffer;
}

#ifdef _WIN32  
std::string __cdecl strext::format(const_char_ptr f, ...)
#else
std::string strext::format(const_char_ptr f, ...)
#endif
{
  va_list arg;
  va_start(arg, f);
  return format_arg(f, arg);
}

std::string strext::format_arg(const_char_ptr f, va_list arg)
{
  std::string result;
#ifdef _WIN32
  int len = _vscprintf(f, arg);
  if (len<=0) return "";
  result.resize(len);
  vsprintf_s(buffer(result), len+1, f, arg);
#else
  va_list arg2;
  va_copy(arg2, arg);

  int len = vsnprintf(NULL, 0, f, arg);
  if (len<=0) return "";
  result.resize(len);
  vsprintf(&result[0], f, arg2);
#endif
  return result;
}

bool strext::starts_width(const std::string& str, const std::string& start)
{
  return str.length() > start.length() && 0==memcmp(str.c_str(), start.c_str(), start.length());
}

bool strext::ends_width(const std::string& str, const std::string& end)
{
  return str.length() > end.length() && 0==memcmp(str.c_str() + str.length() - end.length(), end.c_str(), end.length());
}

std::vector<std::string> strext::tokenize(const std::string& str, const std::string& delim) //static
{
  std::vector<std::string> out;

#ifdef _WIN32
  char_ptr dup = _strdup(str.c_str());
  char *next_token = NULL;  
  const_char_ptr token = strtok_s(dup, delim.c_str(), &next_token);
#else
  char_ptr dup = strdup(str.c_str());
  const_char_ptr token = strtok(dup, delim.c_str());
#endif

  while (token)
  {
    std::string t = token;
    trim(t);
    out.push_back(t); 
#ifdef _WIN32
    token = strtok_s(NULL, delim.c_str(), &next_token);
#else
    token = strtok(NULL, delim.c_str());
#endif
  }

  free(dup);
  return out;
}



namespace ub {

const ascii_t ascii;
const utf8_t    utf8;
const utf16le_t utf16le;
const utf16be_t utf16be;
const utf32le_t utf32le;
const utf32be_t utf32be;
const ucs2le_t  ucs2le;
const ucs2be_t  ucs2be;

int utf8_t::count(const std::string& str) const
{
  int count = 0;
  int size = int(str.length());
  const_char_ptr src = str.c_str();
  while (size>0)
  {
    uint32_t symbol;
    int symbol_len = utf8.get_symbol(symbol, const_byte_ptr(src), size);
    if (!symbol_len) break;
    if (!symbol) break;
    src += symbol_len;
    size -= symbol_len;
    count++;
  }
  return count;
}

uint32_t utf8_t::get_symbol(const std::string& str, int index) const
{
  int size = int(str.length());
  const_char_ptr src = str.c_str();
  uint32_t symbol = 0;
  while (size>0)
  {
    int symbol_len = utf8.get_symbol(symbol, const_byte_ptr(src), size);
    if (!symbol_len) return 0;
    if (!symbol) return 0;
    src += symbol_len;
    size -= symbol_len;
    if (!index) break;
    index--;
  }
  return symbol;
}


int utf8_t::get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const
{
  dst = 0;
  uint8_t b = *src;
  int count=0; uint32_t h=0;

       if ((b & 0x80) == 0x00) { count = 1; h = b; }
  else if ((b & 0xe0) == 0xc0) { count = 2; h = b & 0x1f; }
  else if ((b & 0xf0) == 0xe0) { count = 3; h = b & 0x0f; }
  else if ((b & 0xf8) == 0xf0) { count = 4; h = b & 0x07; }
  else if ((b & 0xfc) == 0xf8) { count = 5; h = b & 0x03; }
  else if ((b & 0xfe) == 0xfc) { count = 6; h = b & 0x01; }
  else return 0; // invalid
  if (src_size<count) return 0;

  uint32_t s=0;
  int bits=0;
  for (int index=1; index<count; index++, bits+=6)
  {
    uint8_t x = src[count-index];
    if ((x & 0xc0) != 0x80) return 0; // invalid
    s |= uint32_t(x & 0x3f) << bits;
  }
  
  dst = s | (h<<bits);
  return count;
}

int utf8_t::put_symbol(byte_ptr dst, uint32_t src) const
{
  if (src<=0x7f)
  {
    if (dst) *dst = (char)src;
    return 1;
  }

  int n=0;
  uint8_t mask = 0;

       if (src <= 0x000007ff) { n = 2; mask = 0xc0; }
  else if (src <= 0x0000ffff) { n = 3; mask = 0xe0; }
  else if (src <= 0x001fffff) { n = 4; mask = 0xf0; }
  else if (src <= 0x03ffffff) { n = 5; mask = 0xf8; }
  else                          { n = 6; mask = 0xfc; }

  if (dst)
  {
    dst += n;
    for (int i=1; i<n; i++, src>>=6) *--dst = 0x80 | uint8_t(src & 0x3f);
    *--dst = mask & uint8_t(src);
  }

  return n;
}

static const unsigned ansi_codes_from_80_to_9f[] = 
{
  0x20AC, '?',    0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021, 0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, '?', 0x017D, '?', 
  '?',    0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, '?', 0x017E, 0x0178, 
};

int ascii_t::get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const 
{
  uint8_t c = *src;
  if (c>=0x80 && c<=0xa0) c = ansi_codes_from_80_to_9f[c-0x80];
  dst = c;

  return 1;
}

int ascii_t::put_symbol(byte_ptr dst, uint32_t src) const 
{
  if (dst)
  {
    uint8_t c='?';
    if (src<0x80) c = uint8_t(src);
    if (src>=0xa0 && src<=0xff) c = uint8_t(src);
    if (src>=0x2100) c = '?';
    if (src<=0x0150) c = '?';
    for (int i=0; i<32; i++)
    {
      if (src==ansi_codes_from_80_to_9f[i]) c = uint8_t(0x80+i);
    }
    *dst = c;
  }

  return 1;
}

int ascii_t::get_codes_count() const { return 128; }
int ascii_t::symbol_to_code(uint32_t s) const { return s<128 ? s : -1; }
uint32_t ascii_t::code_to_symbol(int code) const { return (code>=0 && code<128) ? code : UINT_MAX; }

struct symbol_range_t { int from, to; };

struct symbol_ranges_t
{
  const symbol_range_t* ranges;
  int ranges_count;
  int max_code;
  int max_symbol;
  symbol_ranges_t(int _max_symbol, const symbol_range_t _ranges[], int _ranges_count) : max_symbol(_max_symbol), ranges(_ranges), ranges_count(_ranges_count)
  {
    max_code = max_symbol;
    for (int i=0; i<ranges_count; i++) max_code -= (ranges[i].to - ranges[i].from + 1);
  }
  
  int symbol_to_code(int symbol) const 
  {
    if (symbol>=max_symbol) return -1;

    int code = symbol;
    for (int i=0; i<ranges_count; i++)
    {
      int from = ranges[i].from;
      int to = ranges[i].to;
      if (symbol<from) break;
      if (symbol<=to) return -1;
      code -= (to-from+1);
    }
    return code;
  }

  int code_to_symbol(int code) const 
  {
    int symbol = code;
    for (int i=0; i<ranges_count; i++)
    {
      int from = ranges[i].from;
      int to = ranges[i].to;
      if (symbol<from) break;
      symbol += (to-from+1);
    }
    if (symbol>=max_symbol) return -1;
    return symbol;
  }
};

static const symbol_range_t unicode_non_symbols[] = 
{
  {0x00d800, 0x00dfff},
  {0x00fdd0, 0x00fdef},
  {0x00fffe, 0x00ffff},
  {0x01fffe, 0x01ffff},
  {0x02fffe, 0x02ffff},
  {0x03fffe, 0x03ffff},
  {0x04fffe, 0x04ffff},
  {0x05fffe, 0x05ffff},
  {0x06fffe, 0x06ffff},
  {0x07fffe, 0x07ffff},
  {0x08fffe, 0x08ffff},
  {0x09fffe, 0x09ffff},
  {0x0afffe, 0x0affff},
  {0x0bfffe, 0x0bffff},
  {0x0cfffe, 0x0cffff},
  {0x0dfffe, 0x0dffff},
  {0x0efffe, 0x0effff},
  {0x0ffffe, 0x0fffff},
  {0x10fffe, 0x10ffff},
};

static const symbol_ranges_t utf_ranges(0x110000, unicode_non_symbols, _countof(unicode_non_symbols));
static const symbol_ranges_t ucs_ranges(0x10000,  unicode_non_symbols, 3);

int unicode_t::get_codes_count()  const { return utf_ranges.max_code; }
int unicode_t::symbol_to_code(uint32_t s) const { return utf_ranges.symbol_to_code(s); }
uint32_t unicode_t::code_to_symbol(int code) const {  return utf_ranges.code_to_symbol(code); }

int ucs2le_t::get_codes_count() const { return ucs_ranges.max_code; }
int ucs2le_t::symbol_to_code(uint32_t s) const { return ucs_ranges.symbol_to_code(s); }
uint32_t ucs2le_t::code_to_symbol(int code) const {  return ucs_ranges.code_to_symbol(code); }

int ucs2be_t::get_codes_count() const { return ucs_ranges.max_code; }
int ucs2be_t::symbol_to_code(uint32_t s) const { return ucs_ranges.symbol_to_code(s); }
uint32_t ucs2be_t::code_to_symbol(int code) const {  return ucs_ranges.code_to_symbol(code); }

template <bool be>static int utf16_get_symbol(uint32_t& dst, const_byte_ptr src, int src_size)
{
  dst = 0;
  if (src_size<2) return 0;
  uint32_t w = be ? be_get_2(src) : le_get_2(src);
  if (w<0xd800 || w>0xdbff) { dst=w; return 2; }
  if (src_size<4) return 0;
  uint32_t w2=be ? be_get_2(src+2) : le_get_2(src+2);
  if (w2<0xdc00 || w2>0xdfff) return 0;
  dst = 0x10000 + ((w - 0xd800) << 10) + (w2 - 0xdc00);
  return 4;
}

template<bool be> static int utf16_put_symbol(byte_ptr dst, uint32_t src)
{
  if (src < 0x10000) 
  {
    if (dst) 
    {
      if (be) be_set_2(dst, src); else le_set_2(dst, src);
    }
    return 2;
  }

  if (dst)
  {
    src-=0x10000;
    uint16_t w = 0xd800 + uint16_t(src >> 10);
    if (be) be_set_2(dst, w); else le_set_2(dst, w);
    w = 0xdc00 + uint16_t(src & 0x3ff);
    if (be) be_set_2(dst+2, w); else le_set_2(dst+2, w);
  }
  return 4;
}

int utf16le_t::get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const { return utf16_get_symbol<false>(dst, src, src_size); }
int utf16be_t::get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const { return utf16_get_symbol<true>(dst, src, src_size); }
int utf16le_t::put_symbol(byte_ptr dst, uint32_t src) const { return utf16_put_symbol<false>(dst, src); }
int utf16be_t::put_symbol(byte_ptr dst, uint32_t src) const { return utf16_put_symbol<true>(dst, src); }

int ucs2le_t::get_symbol(uint32_t& dst, const_byte_ptr src, int src_size)  const
{ 
  uint32_t s = utf16le_t::get_symbol(dst, src, src_size); 
  return s<0x10000 ? s : -1;
}

int ucs2be_t::get_symbol(uint32_t& dst, const_byte_ptr src, int src_size) const
{ 
  uint32_t s = utf16be_t::get_symbol(dst, src, src_size); 
  return s<0x10000 ? s : -1;
}

int ucs2le_t::put_symbol(byte_ptr dst, uint32_t src) const { return src<0x10000 ? utf16le_t::put_symbol(dst, src) : 0; }
int ucs2be_t::put_symbol(byte_ptr dst, uint32_t src) const { return src<0x10000 ? utf16be_t::put_symbol(dst, src) : 0; }

int utf32le_t::get_symbol(uint32_t& dst, const_byte_ptr src, int src_size)  const
{ 
  dst = 0;
  if (src_size<4) return 0;
  dst = le_get_4(src);
  return 4;
}

int utf32be_t::get_symbol(uint32_t& dst, const_byte_ptr src, int src_size)  const
{
  dst = 0;
  if (src_size<4) return 0;
  dst = be_get_4(src);
  return 4;
}

int utf32le_t::put_symbol(byte_ptr dst, uint32_t src)  const
{ 
  if (dst) le_set_4(dst, src); 
  return 4;
}

int utf32be_t::put_symbol(byte_ptr dst, uint32_t src) const
{ 
  if (dst) be_set_4(dst, src); 
  return 4;
}

std::string encoding_t::convert(const mem_t src) const
{
  int len = convert(NULL, src);
  if (len<=0) return "";
  std::string result;
  result.resize(len);
  convert(&result[0], src);
  return result;
}

buf_t encoding_t::convert(const_char_ptr src, int size) const
{
  buf_t result;
  int len = convert(NULL, src);
  if (len<=0) return result;
  result.resize(len);
  convert(result.data(), src);
  return result;
}


int encoding_t::convert(char_ptr dst, const mem_t src) const
{
  const_byte_ptr p = src.data;
  int size = src.size;
  int out_size = 0;
  while (size>0)
  {
    uint32_t symbol;
    int symbol_len = get_symbol(symbol, p, size);
    if (!symbol_len) break;
    if (!symbol) break;
    int out_len = utf8.put_symbol(byte_ptr(dst), symbol);
    out_size += out_len;
    if (dst) dst+=out_len;
    p += symbol_len;
    size -= symbol_len;
  }
  return out_size;
}

buf_t encoding_t::convert(const_char_ptr src) const
{
  return convert(src, src ? int(strlen(src)) : 0);
}

int encoding_t::convert(byte_ptr dst, const_char_ptr src) const
{
  return convert(dst, src, src ? int(strlen(src)) : 0);
}

int encoding_t::convert(byte_ptr dst, const_char_ptr src, int size) const
{
  int out_size = 0;
  while (size>0)
  {
    uint32_t symbol;
    int symbol_len = utf8.get_symbol(symbol, const_byte_ptr(src), size);
    if (!symbol_len) break;
    if (!symbol) break;
    int out_len = put_symbol(dst, symbol);
    out_size += out_len;
    if (dst) dst+=out_len;
    src += symbol_len;
    size -= symbol_len;
  }
  return out_size;
}

}

