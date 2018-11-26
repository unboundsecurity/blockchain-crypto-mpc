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

extern bool g_process_termination;

template<class T> class global_t
{
public: 
  global_t() { change_ref_count(+1); } 
  ~global_t() 
  { 
    if (change_ref_count(-1)) return; 
    T* ptr = instance_ptr(false); 
    if (ptr) ptr->~T(); 
  }
  T& instance() { return *instance_ptr(true); }

private:
  static T* instance_ptr(bool force) 
  { 
    static once_t once = once_init;
    if (!force && once!=once_ready) return nullptr;
    static unsigned char buf[sizeof(T)];
    if (once_begin(once))
    {
      new ((T*)buf) T();
      once_end(once);
    }
    return (T*)buf; 
  }
  static int change_ref_count(int x) { static int ref_count = 0; return ref_count += x; }
};

#define GLOBAL_DEFINE(type, func) \
  static ub::global_t<type> global__##func; \
  static type& func() { return global__##func.instance(); }


template<class T> class global_init_t : public global_t<T>
{
public: 
  global_init_t()  : global_t<T>() { global_t<T>::instance(); }
};

class mutex_t
{
  friend class cond_variable_t;
  friend class semaphore_t;

public:
  mutex_t();
  ~mutex_t();
  void lock();
  void unlock();
  bool try_lock();
private:
#ifdef _WIN32
  CRITICAL_SECTION os;
#else
  pthread_mutex_t os;
#endif
};

class scoped_lock_t
{
public:
  scoped_lock_t(mutex_t& the_cs) : cs(the_cs) { cs.lock(); }
  ~scoped_lock_t() { cs.unlock(); }
private:
  scoped_lock_t(); // not implemented
  scoped_lock_t& operator = (scoped_lock_t&); // not implemented
  mutex_t& cs;
};



class thread_t
{
public:
  static uint64_t thread_id();
  static void sleep(int milliseconds);
  static void yield();
};


class tls_base_t
{
public:
  static void thread_detach(void_ptr* data=nullptr);
  static void process_detach();
  typedef void* (*new_instance_t)();
  typedef void  (*delete_instance_t)(void* ptr);
  tls_base_t(new_instance_t new_instance, delete_instance_t delete_instance);

protected:
  int index;
  void_ptr get() { return get(index); }
  static void_ptr get(int index);
};

template <typename T> class tls_def_t : public tls_base_t
{
public:
  tls_def_t() : tls_base_t(new_instance, delete_instance) {}
  T& instance() { return *(T*)get(); }

private:
  static void* new_instance() { return new T; }
  static void delete_instance(void* ptr) { delete (T*)ptr; }
};


#define TLS_DEFINE(type, func) \
  static ub::global_t< ub::tls_def_t<type> > tls__##func; \
  static type& func() { return tls__##func.instance().instance(); }

template <typename T> class tls_t
{
public:
  T& instance() { return global.instance().instance(); }
private:
  global_t< tls_def_t<T> > global;
};


} //namespace ub
