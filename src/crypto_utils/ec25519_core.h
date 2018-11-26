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

#include <stdint.h>

namespace ec25519_core
{

/* fe means field element. Here the field is \Z/(2^255-19). An element t,
 * entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
 * t[3]+2^102 t[4]+...+2^230 t[9]. Bounds on each t[i] vary depending on
 * context.  */
typedef int32_t fe[10];

/* ge means group element.

 * Here the group is the set of pairs (x,y) of field elements (see fe.h)
 * satisfying -x^2 + y^2 = 1 + d x^2y^2
 * where d = -121665/121666.
 *
 * Representations:
 *   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
 *   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
 *   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
 *   ge_precomp (Duif): (y+x,y-x,2dxy) */

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p1p1;

typedef struct {
  fe yplusx;
  fe yminusx;
  fe xy2d;
} ge_precomp;

typedef struct {
  fe YplusX;
  fe YminusX;
  fe Z;
  fe T2d;
} ge_cached;

void ge_scalarmult_base(ge_p3 *h, const uint8_t *a);
void ge_p3_tobytes(uint8_t *s, const ge_p3 *h);
void ge_double_scalarmult_vartime(ge_p2 *r, const uint8_t *a, const ge_p3 *A, const uint8_t *b);
int ge_frombytes_vartime(ge_p3 *h, const uint8_t *s);
void ge_tobytes(uint8_t *s, const ge_p2 *h);
void ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p);
void ge_p3_to_cached(ge_cached *r, const ge_p3 *p);
void ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p);
void ge_p3_0(ge_p3 *h);
void x25519_sc_reduce(uint8_t *s);
void sc_muladd(uint8_t *s, const uint8_t *a, const uint8_t *b, const uint8_t *c);

int ED25519_sign(uint8_t *out_sig, const uint8_t *message, size_t message_len, const uint8_t public_key[32], const uint8_t private_key[32]);
int ED25519_verify(const uint8_t *message, size_t message_len, const uint8_t signature[64], const uint8_t public_key[32]);
int ED25519_sign_with_scalar(uint8_t *out_sig, const uint8_t *message, size_t message_len, const uint8_t public_key[32], const uint8_t scalar[32]);

} //namespace ec25519_core
