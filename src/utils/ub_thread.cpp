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


namespace ub {

bool g_process_termination = false;

int atomic_add(volatile int& value, int count)
{
#if defined(_WIN32)
  return (int)::InterlockedExchangeAdd((volatile long*)&value, count) + count;
#elif defined(__APPLE__)
  return OSAtomicAdd32(count, &value);
#else // __linux__
  return __sync_add_and_fetch(&value, count);
#endif
}

int atomic_sub(volatile int& value, int count)
{
#if defined(_WIN32)
  return (int)::InterlockedExchangeAdd((volatile long*)&value, -count) - count;
#elif defined(__APPLE__)
  return OSAtomicAdd32(-count, &value);
#else // __linux__
  return __sync_sub_and_fetch(&value, count);
#endif
}

int atomic_inc(volatile int& value)
{
#if defined(_WIN32)
  return (int)::InterlockedIncrement((volatile long*)&value);
#elif defined(__APPLE__)
  return OSAtomicIncrement32(&value);
#else // __linux__
  return __sync_add_and_fetch(&value, 1);
#endif
}

#ifndef __ANDROID__
int64_t atomic_inc(volatile int64_t& value)
{
#if defined(_WIN32)
  return ::InterlockedIncrement64((volatile LONGLONG*)&value);
#elif defined(__APPLE__)
  return OSAtomicIncrement64(&value);
#else // __linux__
  return __sync_add_and_fetch(&value, 1);
#endif
}
#endif

int atomic_dec(volatile int& value)
{
#if defined(_WIN32)
  return (int)::InterlockedDecrement((volatile long*)&value);
#elif defined(__APPLE__)
  return OSAtomicDecrement32(&value);
#else // __linux__
  return __sync_sub_and_fetch(&value, 1);
#endif
}

#ifndef __ANDROID__
int64_t atomic_dec(volatile int64_t& value)
{
#if defined(_WIN32)
  return (uint64_t)::InterlockedDecrement64((volatile LONGLONG*)&value);
#elif defined(__APPLE__)
  return OSAtomicDecrement64((int64_t*)&value);
#else // __linux__
  return __sync_sub_and_fetch(&value, 1);
#endif
}
#endif

bool atomic_compare_exhange(volatile int& value, int old_value, int new_value)
{
#if defined(_WIN32)
  return old_value==::InterlockedCompareExchange((volatile long*)&value, new_value, old_value);
#elif defined(__APPLE__)
  return OSAtomicCompareAndSwapInt(old_value, new_value, &value);
#else // __linux__
  return __sync_bool_compare_and_swap(&value, old_value, new_value);
#endif
}

#ifndef __ANDROID__
bool atomic_compare_exhange(volatile int64_t& value, int64_t old_value, int64_t new_value)
{
#if defined(_WIN32)
  return old_value==::InterlockedCompareExchange64((volatile __int64*)&value, new_value, old_value);
#elif defined(__APPLE__)
  return OSAtomicCompareAndSwap64(old_value, new_value, &value);
#else // __linux__
  return __sync_bool_compare_and_swap(&value, old_value, new_value);
#endif
}
#endif

#ifndef __APPLE__
bool atomic_compare_exhange_ptr(volatile void_ptr& value, void_ptr old_value, void_ptr new_value)
{
#if defined(_WIN32)
  return old_value==::InterlockedCompareExchangePointer ((volatile PVOID*)&value, new_value, old_value);
#elif defined(__APPLE__)
  return OSAtomicCompareAndSwapPtr(old_value, new_value, &value);
#else // __linux__
  return __sync_bool_compare_and_swap(&value, old_value, new_value);
#endif
}
#endif
  
bool once_begin(once_t& once)
{
  if (once==once_ready) return false;
  if (atomic_compare_exhange(once, once_init, once_busy)) return true;
  while (once!=once_ready) 
  {
    thread_t::yield();
  }
  return false;
}

void once_end(once_t& once)
{
  once = once_ready;
}


mutex_t::mutex_t()
{
#ifdef _WIN32
  ::InitializeCriticalSection(&os);
#else
  pthread_mutexattr_t attr;
  pthread_mutexattr_init(&attr);
#ifdef __APPLE__
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
#else
  pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE_NP);
#endif
  pthread_mutex_init(&os, &attr);
  pthread_mutexattr_destroy(&attr);
#endif
}

mutex_t::~mutex_t()
{
#ifdef _WIN32
  ::DeleteCriticalSection(&os);
#else
  pthread_mutex_destroy(&os);
#endif
}

void mutex_t::lock()
{
#ifdef _WIN32
  ::EnterCriticalSection(&os);
#else
  pthread_mutex_lock(&os);
#endif
}

void mutex_t::unlock()
{
#ifdef _WIN32
  ::LeaveCriticalSection(&os);
#else
  pthread_mutex_unlock(&os);
#endif
}

bool mutex_t::try_lock()
{
#ifdef _WIN32
  return FALSE!=::TryEnterCriticalSection(&os);
#else
  return 0==pthread_mutex_trylock(&os);
#endif
}


//--------------------------------- thread_t ----------------------------

uint64_t thread_t::thread_id()
{
#ifdef _WIN32
  return ::GetCurrentThreadId();
#elif defined(__APPLE__)
  uint64_t id = 0;
  pthread_threadid_np(NULL, &id);
  return id;
#elif defined(__ANDROID__)
  return gettid();
#else
  return syscall(SYS_gettid);
#endif
}

void thread_t::yield()
{
#if defined(_WIN32)
  ::SwitchToThread();
#elif defined(__APPLE__)
  sched_yield();
#else
  sched_yield();
#endif
}


void thread_t::sleep(int milliseconds)
{
#ifdef _WIN32
  ::Sleep(milliseconds);
#else
  usleep(milliseconds*1000);
#endif
}

//------------------------- TLS ----------------------

static const int tls_max = 64;
static volatile int tls_count = 0;
static struct { tls_base_t::new_instance_t new_instance; tls_base_t::delete_instance_t delete_instance; } tls_tab[tls_max] = {0};


#if defined(_WIN64)
#define THREAD_LOCAL __declspec(thread)
//#elif !defined(_WIN32) && !defined(TARGET_OS_IOSX)
//#define THREAD_LOCAL __thread
#endif


#ifdef THREAD_LOCAL
static THREAD_LOCAL void* tls_data = nullptr;
#define tls_get_ptr()   tls_data
#define tls_set_ptr(p)  tls_data = (void*)(p)
#define tls_free()
#else
#ifdef _WIN32
static DWORD tls_handle = -1;
#define tls_get_ptr()   ::TlsGetValue(tls_handle)
#define tls_set_ptr(p)  ::TlsSetValue(tls_handle, p)
#define tls_free()      ::TlsFree(tls_handle)
#else
static pthread_key_t tls_handle = {0};
static void tls_free_data(void* data_ptr) { tls_base_t::thread_detach((void_ptr*)data_ptr); }
#define tls_get_ptr()   pthread_getspecific(tls_handle)
#define tls_set_ptr(p)  pthread_setspecific(tls_handle, p)
#define tls_free()      pthread_key_delete(tls_handle)
#endif
static once_t tls_once = once_init;
#endif

void tls_base_t::thread_detach(void_ptr* data)
{
  if (g_process_termination) return;

#ifndef THREAD_LOCAL
  if (tls_once != once_ready) return;
#endif

  if (!data) data = (void_ptr*)tls_get_ptr();
  if (!data) return;
  for (int i=tls_count-1; i>=0; i--)
  {
    tls_tab[i].delete_instance(data[i]);
  }
  delete[] data;
  tls_set_ptr(nullptr);
};

void tls_base_t::process_detach()
{
  if (g_process_termination) return;

#ifndef THREAD_LOCAL
  if (tls_once != once_ready) return;
#endif

  thread_detach(); 
  tls_free();
}

tls_base_t::tls_base_t(new_instance_t new_instance, delete_instance_t delete_instance)
{
  index = atomic_inc(tls_count)-1;
  assert(index<tls_max);
  tls_tab[index].new_instance = new_instance;
  tls_tab[index].delete_instance = delete_instance;
}

void_ptr tls_base_t::get(int index) // static
{
#ifdef THREAD_LOCAL
  void_ptr* data = (void_ptr*)tls_data;
#else
  if (once_begin(tls_once))
  {
#ifdef _WIN32
    tls_handle = ::TlsAlloc();
#else
    pthread_key_create(&tls_handle, tls_free_data);
#endif
    once_end(tls_once);
  }
  void_ptr* data = (void_ptr*)tls_get_ptr();
#endif

  if (!data) 
  {
    data = new void_ptr[tls_max];
    memset(data, 0, tls_max*sizeof(void*));
    tls_set_ptr(data);
  }

  void_ptr ptr = data[index];
  if (!ptr) 
  {
    ptr = data[index] = tls_tab[index].new_instance();
  }
  return ptr;
}




} // namespace

#ifdef _WIN32


BOOL WINAPI DllMain( HINSTANCE hInstance, DWORD dwReason, LPVOID plvReserved)
{
  switch (dwReason)
  {
    case DLL_THREAD_DETACH:
      ub::tls_base_t::thread_detach();
      break;

    case DLL_PROCESS_DETACH:
      if (plvReserved)  { ub::g_process_termination = true; return TRUE; }
      ub::tls_base_t::process_detach();
      break;
  }

  return TRUE;
}
#endif
