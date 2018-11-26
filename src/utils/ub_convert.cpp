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
#include "ub_convert.h"
#include "ub_buf256.h"

namespace ub
{

void converter_t::convert(bool& value)
{
  uint8_t v = value ? 1 : 0;
  convert(v);
  if (!error && !write) value = v!=0;
}

void converter_t::convert(uint8_t& value)
{
  if (write)
  {
    if (pointer) *current() = value;
  }
  else
  {
    if (error || !at_least(1)) { error = true; return; }
    value = *current();
  }
  forward(1);
}

void converter_t::convert(int8_t& value)
{
  uint8_t v = value;
  convert(v);
  if (!error && !write) value = v;
}

void converter_t::convert(uint16_t& value)
{
  if (write)
  {
    if (pointer) ub::be_set_2(current(), value);
  }
  else
  {
    if (error || !at_least(2)) { error = true; return; }
    value = ub::be_get_2(current());
  }
  forward(2);
}

void converter_t::convert(int16_t& value)
{
  uint16_t v = value;
  convert(v);
  if (!error && !write) value = v;
}

void converter_t::convert(uint32_t& value)
{
  if (write)
  {
    if (pointer) ub::be_set_4(current(), value);
  }
  else
  {
    if (error || !at_least(4)) { error = true; return; }
    value = ub::be_get_4(current());
  }
  forward(4);
}

void converter_t::convert(int32_t& value)
{
  uint32_t v = value;
  convert(v);
  if (!error && !write) value = v;
}

void converter_t::convert(uint64_t& value)
{
  if (write)
  {
    if (pointer) ub::be_set_8(current(), value);
  }
  else
  {
    if (error || !at_least(8)) { error = true; return; }
    value = ub::be_get_8(current());
  }
  forward(8);
}

void converter_t::convert(int64_t& value)
{
  uint64_t v = value;
  convert(v);
  if (!error && !write) value = v;
}

void converter_t::convert(double& value)
{
  uint64_t v = *(uint64_t*)&value;
  convert(v);
  if (!error && !write) value = *(double*)&v;
}

void converter_t::convert(std::string& value)
{
  short value_size = (short)value.length();
  convert(value_size);

  if (write)
  {
    if (pointer) memmove(current(), &value[0], value_size);
  }
  else
  {
    if (value_size<0) { error = true; return; }
    if (error || !at_least(value_size)) { error = true; return; }
    value.resize(value_size);
    memmove(&value[0], current(), value_size);
  }
  forward(value_size);
}

converter_t::converter_t(bool _write) : write(_write), error(false), pointer(nullptr), offset(0), size(0)
{
}

converter_t::converter_t(byte_ptr out) : write(true), error(false), pointer(out), offset(0), size(0)
{
}


converter_t::converter_t(mem_t src) : write(false), error(false), pointer(src.data), offset(0), size(src.size)
{
}

void converter_t::set_error()
{
  if (!error) ub::error(E_FORMAT, "Converter error" + std::string(write ? "(write)" : "(read)"));
  error = true;
}

void converter_t::convert_len(uint32_t& len)
{
  uint16_t hi = 0;
  uint16_t lo = 0;

  if (write)
  {
    if (len < 0x8000)
    {
      lo = uint16_t(len);
    }
    else
    {
      hi = uint16_t((len>>16) | 0x8000);
      lo = uint16_t(len);
      convert(hi);
    }
    convert(lo);
  }
  else
  {
    convert(hi);
    if (hi & 0x8000)
    {
      convert(lo);
      len = (uint32_t(hi & 0x7fff) << 16) | lo;
    }
    else len = hi;
  }
}

convertable_t::version_t::version_t(converter_t& _converter, uint8_t version) : converter(_converter), value(version)
{
  size_ptr = converter.current();
  converter.forward(2); // for size
  converter.convert(version);
}

convertable_t::version_t::~version_t()
{
  if (converter.is_error()) return;
  int size = int(converter.current()-size_ptr-2);
  if (converter.is_write()) 
  {
    if (!converter.is_calc_size()) be_set_2(size_ptr, size);
  }
  else
  {
    int full_size = unsigned(be_get_2(size_ptr));
    if (full_size<size) { converter.set_error(); return; }
    converter.forward(full_size-size);
  }
}

void converter_t::convert(std::vector<bool>& value)
{
  if (!write) value.clear();

  short count = (short)value.size();
  convert(count);

	if (!write) value.resize(count);
	for (short i = 0; i<count && !error; i++) 
  {
    bool v = value[i];
    convert(v);
    value[i] = v;
  }
}

void convertable_t::factory_t::register_type(def_t* def, uint64_t code_type)
{
  g_convertable_factory.instance().map[code_type] = def;
}

convertable_t* convertable_t::factory_t::create(uint64_t code_type)
{
  const auto& map = g_convertable_factory.instance().map; 
  const auto i = map.find(code_type);
  if (i==map.end()) return nullptr;
  return i->second->create();
}

convertable_t* convertable_t::factory_t::create(mem_t mem, bool convert)
{
  if (mem.size<sizeof(uint64_t)) return nullptr;

  uint64_t code_type = be_get_8(mem.data);
  convertable_t* obj = create(code_type);
  if (!convert) return obj;

  if (!obj) return nullptr;
  
  converter_t converter(mem);
  obj->convert(converter);
  if (!converter.is_error()) return obj;

  delete obj;
  return nullptr;
}

uint64_t converter_t::convert_code_type(uint64_t code, uint64_t code2, uint64_t code3, uint64_t code4, uint64_t code5, uint64_t code6, uint64_t code7, uint64_t code8)
{
  uint64_t value = code;
  convert(value);
  if (error) return 0;
  if (!write)
  {
    if (value==code) return value;
    if (code2 && value==code2) return value;
    if (code3 && value==code3) return value;
    if (code4 && value==code4) return value;
    if (code5 && value==code5) return value;
    if (code6 && value==code6) return value;
    if (code7 && value==code7) return value;
    if (code8 && value==code8) return value;
    set_error();
    return 0;
  }
  return value;
}


} // namespace ub
