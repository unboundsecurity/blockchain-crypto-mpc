# 
#  NOTICE
# 
#  The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
#  If you choose to receive it under the GPL v.3 license, the following applies:
#  Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
#  
#  Copyright (C) 2018, Unbound Tech Ltd. 
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
# 
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
# 
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
# 
  
# ---------------- COMMON -------------------------
COMMON_INCLUDES = \
	-I include

COMMON_CPPFLAGS = \
	-O2 \
	-fPIC \
	-fno-strict-aliasing \
	-Wno-unused \
	-Wno-switch \
	-Wno-switch-enum \
	-Werror \
	-mpclmul \
	-std=c++0x

COMMON_LDFLAGS = \
	-s

#---------------- LIB -------------------
	
LIB_CPPSRC = $(wildcard src/*.cpp) \
	$(wildcard src/utils/*.cpp) \
	$(wildcard src/crypto_utils/*.cpp) \
	$(wildcard src/mpc_protocols/*.cpp)
		 
LIB_ASMSRC = \
	$(wildcard src/mpc_protocols/*.s)
		 
LIB_OBJ = \
	$(LIB_CPPSRC:.cpp=.o) \
	$(LIB_ASMSRC:.s=.o) 

LIB_HEADERS = $(wildcard src/*.h) \
	$(wildcard src/utils/*.h) \
	$(wildcard src/crypto_utils/*.h) \
	$(wildcard src/mpc_protocols/*.h)
	
LIB_INCLUDES = \
	$(COMMON_INCLUDES) \
	-I /usr/lib/jvm/java-8-oracle/include \
	-I /usr/lib/jvm/java-8-oracle/include/linux \
	-I src/utils \
	-I src/crypto_utils \
	-I src/mpc_protocols
	

LIB_CPPFLAGS = \
	$(COMMON_CPPFLAGS) \
	-DMPC_CRYPTO_EXPORTS \
	-fvisibility=hidden \
	-maes

LIB_LDFLAGS = \
	$(COMMON_LDFLAGS) \
	-Wl,-z,defs \
	-Wl,-rpath,\'\$$ORIGIN\' \
	-shared \
	-rdynamic \
	-lcrypto \
	-lpthread

.s.o: 
	$(CXX) -o $@ -c $<

src/utils/precompiled.h.gch: src/utils/precompiled.h
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

src/utils/%.o: src/utils/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<
   
src/crypto_utils/%.o: src/crypto_utils/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

src/mpc_protocols/%.o: src/mpc_protocols/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

src/%.o: src/%.cpp src/utils/precompiled.h.gch
	$(CXX) $(LIB_CPPFLAGS) $(LIB_INCLUDES) -o $@ -c $<

libmpc_crypto.so: $(LIB_OBJ)
	$(CXX) -o $@ $^ $(LIB_LDFLAGS)

#----------------------- TEST --------------------------	
	
TEST_SRC = \
	$(wildcard test/*.cpp)

TEST_OBJ = \
	$(TEST_SRC:.cpp=.o)
	
TEST_CPPFLAGS = \
	$(COMMON_CPPFLAGS)
  
TEST_INCLUDES = \
	$(COMMON_INCLUDES) \
	-I src
	
TEST_LDFLAGS = \
	$(COMMON_LDFLAGS) \
	-L . \
	-lmpc_crypto

  
test/%.o: test/%.cpp
	$(CXX) $(TEST_CPPFLAGS) $(TEST_INCLUDES) -o $@ -c $<

mpc_crypto_test: $(TEST_OBJ) libmpc_crypto.so
	$(CXX) -o $@ $^ $(TEST_LDFLAGS)

#----------------------- BENCH --------------------------	
	
BENCH_SRC = \
	$(wildcard bench/*.cpp)

BENCH_OBJ = \
	$(BENCH_SRC:.cpp=.o)
	
BENCH_CPPFLAGS = \
	$(COMMON_CPPFLAGS)
  
BENCH_INCLUDES = \
	$(COMMON_INCLUDES) \
	-I src
	
BENCH_LDFLAGS = \
	$(COMMON_LDFLAGS) \
	-L . \
	-lmpc_crypto

  
bench/%.o: bench/%.cpp
	$(CXX) $(BENCH_CPPFLAGS) $(BENCH_INCLUDES) -o $@ -c $<

mpc_crypto_bench: $(BENCH_OBJ) libmpc_crypto.so
	$(CXX) -o $@ $^ $(BENCH_LDFLAGS)

#---------------------------------------------------------
	
.PHONY: clean

clean:
	rm -f $(LIB_OBJ) $(TEST_OBJ) mpc_crypto_test mpc_crypto_bench libmpc_crypto.so src/utils/precompiled.h.gch
	
.DEFAULT_GOAL := mpc_crypto_bench
