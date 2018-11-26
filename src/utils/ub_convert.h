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

struct buf128_t;
struct buf256_t;

namespace ub {

class converter_t;

class convertable_t // interface
{
public:
  virtual void convert(converter_t& converter) = 0;
  virtual ~convertable_t(){}

  class version_t
  {
  public:
    version_t(converter_t& converter, uint8_t version=0);
    ~version_t();
    uint8_t get() const { return value; }

  private:
    byte_ptr size_ptr;
    uint8_t value;
    converter_t& converter;
  };

  class def_t
  {
  public:
    virtual ~def_t() {}
    virtual convertable_t* create() = 0;
  };

  template<class type, uint64_t code_type>
  class def_entry_t : public def_t
  {
  public:
    def_entry_t() { factory_t::register_type(this, code_type); }
    virtual convertable_t* create() { return new type(); }
  };

  class factory_t
  {
  private:
    unordered_map_t<uint64_t, def_t*> map;
  public:
    static void register_type(def_t* def, uint64_t code_type);
    static convertable_t* create(mem_t data, bool convert=true);
    static convertable_t* create(uint64_t code_type);

    template<class type, uint64_t code_type>
    class register_t : public global_init_t< def_entry_t<type, code_type> > { };
  };

};

static global_t<convertable_t::factory_t> g_convertable_factory;


class converter_t
{
public:
  template <class T> static int convert(const T& src, byte_ptr out)
  {
    converter_t converter(true);
    converter.pointer = out;
    converter.convert((T&)src);
    return converter.offset;
  }

	converter_t(bool write);
	converter_t(byte_ptr out);
  converter_t(mem_t src);

  bool is_calc_size() const { return !pointer; }
  bool is_write() const { return write; }
  bool is_error() const { return error; }
  void set_error();
  byte_ptr current() const { return pointer+offset; }
  bool at_least(int n) const { return offset+n<=size; }
  void forward(int n) { offset += n; }
  int get_size() const { return write ? offset : size; }
  int get_offset() const { return offset; }
  
  void convert(null_data_t& value) {}
  void convert(bool& value);
  void convert(uint8_t& value);
  void convert(uint16_t& value);
  void convert(uint32_t& value);
  void convert(uint64_t& value);
  void convert(int8_t& value);
  void convert(int16_t& value);
  void convert(int32_t& value);
  void convert(int64_t& value);
  void convert(double& value);
  void convert(std::string& value);

  void convert_len(uint32_t& len);
  
  template<class T> void convert(T& value) { value.convert(*this); }

  uint64_t convert_code_type(uint64_t code, uint64_t code2=0, uint64_t code3=0, uint64_t code4=0, uint64_t code5=0, uint64_t code6=0, uint64_t code7=0, uint64_t code8=0);

  template <typename T, size_t size> void convert(T (&arr)[size])
  {
    for (int i = 0; i < size; ++i) convert(arr[i]);
  }

  template <typename T> void convert(std::vector<T>& value)
  {
    if (!write) value.clear();

    uint32_t count = (uint32_t)value.size();
    convert_len(count);

	  if (!write) value.resize(count);
	  for (uint32_t i = 0; i<count && !error; i++) convert(value[i]);
  }
  
  void convert(std::vector<bool>& value);

  template <typename T> void convert(std::list<T>& value)
  {
    if (!write) value.clear();

    short count = (short)value.size();
    convert(count);
    auto v = value.begin();
    for (short i=0; i<count && !error; i++) 
    {
      if (write)
      {
        convert(*v++);
      }
      else
      {
        T item;
        convert(item);
        value.push_back(item);
      }
    }
  }


  template <typename TKey, typename TItem> void convert(std::map<TKey, TItem>& value)
  {
    if (!write) value.clear();
    short count = (short)value.size();
    convert(count);
    auto v = value.begin();
    for (short i=0; i<count && !error; i++) 
    {
      if (write)
      {
        TKey key = v->first;
        convert(key);
        convert(v->second);
        v++;
      }
      else
      {
        TKey key;
        TItem item;
        convert(key);
        convert(item);
        value[key]=item;
      }
    }
  }

  template <typename TKey, typename TItem> void convert(unordered_map_t<TKey, TItem>& value)
  {
    if (!write) value.clear();
    short count = (short)value.size();
    convert(count);
    auto v = value.begin();
    for (short i=0; i<count && !error; i++) 
    {
      if (write)
      {
        TKey key = v->first;
        convert(key);
        convert(v->second);
        v++;
      }
      else
      {
        TKey key;
        TItem item;
        convert(key);
        convert(item);
        value[key]=item;
      }
    }
  }

protected:
  bool write, error;
  byte_ptr pointer;
  int offset, size;
};


template <class T> buf_t convert(const T& src)
{
  int size = converter_t::convert(src, nullptr);
  buf_t result(size);
  converter_t::convert(src, result.data());
  return result;
}

template <class T> bool convert(T& dst, mem_t src)
{
  converter_t converter(src);
  converter.convert(dst);
  return !converter.is_error();
}

template <class T> int convert_head(T& dst, mem_t src)
{
  converter_t converter(src);
  converter.convert(dst);
  if (converter.is_error()) return 0;
  return converter.get_offset();
}

} // namespace ub


