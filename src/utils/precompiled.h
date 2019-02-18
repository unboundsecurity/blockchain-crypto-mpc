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


#ifdef __linux__

#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <syslog.h>
#include <poll.h>
#include <link.h>

#if defined(_LP64) && defined(__x86_64__) // !defined(__ANDROID__)
extern "C"
{
#include <x86intrin.h>
//#include <wmmintrin.h>
}
#endif
#endif


#include <limits.h>
#include <assert.h>
#include <stdarg.h>
#include <stdint.h>
#ifndef __STDC_FORMAT_MACROS
#define __STDC_FORMAT_MACROS
#endif
#include <inttypes.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <fcntl.h>
#include <errno.h>
#include <math.h>

#include <string>
#include <memory>
#include <algorithm>
#include <list>
#include <vector>
#include <queue>
#include <set>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include <ctime>

#if defined(_WIN32) || defined(__APPLE__) || defined(__ANDROID__)
#include <unordered_map>
#include <unordered_set>
#else
#include <tr1/unordered_map>
#include <tr1/unordered_set>
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>
#include <shlwapi.h>
#include <shellapi.h>
#include <shlobj.h>
#include <sddl.h>
#include <tchar.h>
#include <io.h>
#include <sys/stat.h>

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#ifdef max
#undef max
#endif

#ifdef min
#undef min
#endif

#else

#include <dirent.h>
#include <unistd.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef __APPLE__
#include <malloc/malloc.h>
#include <mach/mach_time.h>
#include <libkern/OSAtomic.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pwd.h>
#else
#include <sys/sysinfo.h>
#include <sys/wait.h>
#include <malloc.h>
#include <unistd.h>
#include <semaphore.h>
#endif
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <pthread.h>
#include <termios.h>
#include <netdb.h>
#endif


#ifdef __aarch64__
#include <arm_neon.h>
#endif

#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/objects.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/ec.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/hmac.h>
#include <openssl/cmac.h>
#include <openssl/ssl.h>
#include <openssl/asn1.h>
