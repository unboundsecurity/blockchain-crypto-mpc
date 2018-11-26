/*
 *     NOTICE
 *
 *     The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
 *     If you choose to receive it under the GPL v.3 license, the following applies:
 *     Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.
 *     
 *     Copyright (C) 2018, Unbound Tech Ltd. 
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


.equ  gate_type,         0
.equ  gate_input0,       4
.equ  gate_input1,       8
.equ  gate_output,       12

.equ sched0,             %xmm14
.equ sched1,             %xmm1
.equ sched2,             %xmm2
.equ sched3,             %xmm3
.equ sched4,             %xmm4
.equ sched5,             %xmm5
.equ sched6,             %xmm6
.equ sched7,             %xmm7
.equ sched8,             %xmm8
.equ sched9,             %xmm9
.equ sched10,            %xmm10

.equ e1,                 %xmm11
.equ e2,                 %xmm12
.equ e3,                 %xmm13
.equ e4,                 %xmm14
.equ delta,              %xmm15

.equ count,              %edi #ecx
.equ gates,              %rsi #rdx
.equ garbled,            %rdx #r8
.equ wires,              %rcx #r9

.equ index,              %ebx
.equ input0,             %r9  #rsi
.equ input1,             %r10 #rdi
.equ output,             %r11
.equ fixed_aes_key,      %r8  #r11

.equ input0_index,       %r9d
.equ input1_index,       %r10d
.equ output_index,       %r11d

.equ gc_gate_type,       %eax

.text
.globl gc_garble
gc_garble:

  push             %rbx
  push             %rbp
  mov              %rsp,                           %rbp

  and              $0xfffffffffffffff0,            %rsp

  sub              $64,                            %rsp
  movdqa           %xmm12,                         (%rsp)
  movdqa           %xmm13,                         0x10(%rsp)
  movdqa           %xmm14,                         0x20(%rsp)
  movdqa           %xmm15,                         0x30(%rsp)

  movdqa           %xmm0,                          delta
  sub              $64,                            %rsp

  movdqa           0x010(fixed_aes_key),           sched1
  movdqa           0x020(fixed_aes_key),           sched2
  movdqa           0x030(fixed_aes_key),           sched3
  movdqa           0x040(fixed_aes_key),           sched4
  movdqa           0x050(fixed_aes_key),           sched5
  movdqa           0x060(fixed_aes_key),           sched6
  movdqa           0x070(fixed_aes_key),           sched7
  movdqa           0x080(fixed_aes_key),           sched8
  movdqa           0x090(fixed_aes_key),           sched9
  movdqa           0x0a0(fixed_aes_key),           sched10

  xor              %rbx,                           %rbx # index

gc_garble_start:
  mov              gate_type(gates),               gc_gate_type
  mov              gate_input0(gates),             input0_index
  mov              gate_input1(gates),             input1_index
  mov              gate_output(gates),             output_index
  add              $16,                            gates

  add              input0_index,                   input0_index
  add              input1_index,                   input1_index
  add              output_index,                   output_index

  lea              (wires,input0,8),               input0
  lea              (wires,input1,8),               input1
  lea              (wires,output,8),               output

#XOR_gate:
  movdqa           (input0),                       %xmm0
  cmp              $2,                             gc_gate_type #XOR
  jne              gc_garble_AND_gate

  pxor             (input1),                       %xmm0
  movdqa           %xmm0,                          (output)

  inc              index
  cmp              count,                          index
  jne              gc_garble_start
  jmp              gc_garble_finished

gc_garble_NOT_gate:
  pxor             delta,                          %xmm0
  movdqa           %xmm0,                          (output)

  inc              index
  cmp              count,                          index
  jne              gc_garble_start
  jmp              gc_garble_finished

gc_garble_AND_gate:
  cmp              $3,                             gc_gate_type # AND
  jne              gc_garble_NOT_gate

  movdqa           %xmm0,                          e1
  movdqa           (input1),                       e3
  movdqa           e1,                             e2
  pxor             delta,                          e2
  movdqa           e3,                             e4
  pxor             delta,                          e4

  psllq            $1,                             e1
  psllq            $1,                             e2
  psllq            $1,                             e3
  psllq            $1,                             e4

  movd	           index,                          %xmm0
  pxor             %xmm0,                          e1
  pxor             %xmm0,                          e2

  mov              index,                          %eax
  add              count,                          %eax
  movd	           %eax,                           %xmm0
  pxor             %xmm0,                          e3
  pxor             %xmm0,                          e4

  movdqa           (fixed_aes_key),                %xmm0

  movdqa           e1,                             (%rsp)
  movdqa           e2,                             0x10(%rsp)
  movdqa           e3,                             0x20(%rsp)
  movdqa           e4,                             0x30(%rsp)

  pxor             %xmm0,                          e1
  pxor             %xmm0,                          e2
  pxor             %xmm0,                          e3
  pxor             %xmm0,                          e4

  aesenc           sched1,                         e1
  aesenc           sched1,                         e2
  aesenc           sched1,                         e3
  aesenc           sched1,                         e4

  aesenc           sched2,                         e1
  aesenc           sched2,                         e2
  aesenc           sched2,                         e3
  aesenc           sched2,                         e4

  aesenc           sched3,                         e1
  aesenc           sched3,                         e2
  aesenc           sched3,                         e3
  aesenc           sched3,                         e4

  aesenc           sched4,                         e1
  aesenc           sched4,                         e2
  aesenc           sched4,                         e3
  aesenc           sched4,                         e4

  aesenc           sched5,                         e1
  aesenc           sched5,                         e2
  aesenc           sched5,                         e3
  aesenc           sched5,                         e4

  aesenc           sched6,                         e1
  aesenc           sched6,                         e2
  aesenc           sched6,                         e3
  aesenc           sched6,                         e4

  aesenc           sched7,                         e1
  aesenc           sched7,                         e2
  aesenc           sched7,                         e3
  aesenc           sched7,                         e4

  aesenc           sched8,                         e1
  aesenc           sched8,                         e2
  aesenc           sched8,                         e3
  aesenc           sched8,                         e4

  aesenc           sched9,                         e1
  aesenc           sched9,                         e2
  aesenc           sched9,                         e3
  aesenc           sched9,                         e4

  aesenclast       sched10,                        e1
  aesenclast       sched10,                        e2
  aesenclast       sched10,                        e3
  aesenclast       sched10,                        e4

  pxor             (%rsp),                         e1
  pxor             0x10(%rsp),                     e2
  pxor             0x20(%rsp),                     e3
  pxor             0x30(%rsp),                     e4

  movdqa           e4,                             %xmm0    # x4=e4

  pxor             e1,                             e2
  pxor             e3,                             e4
  pxor             (input0),                       e4

  testb            $1,                             (input1)
  jz               gc_garble_not_lsb_1
  pxor             delta,                          e2
  movdqa           %xmm0,                          e3

gc_garble_not_lsb_1:
  testb            $1,                             (input0)
  jz               gc_garble_not_lsb_0
  pxor             e2,                             e1

gc_garble_not_lsb_0:
  movdqa           e2,                             (garbled)
  add              $16,                            garbled
  movdqa           e4,                             (garbled)
  add              $16,                            garbled

  pxor             e3,                             e1
  movdqa           e1,                             (output)

  inc              index
  cmp              count,                          index
  jne              gc_garble_start

gc_garble_finished:
  add              $64,                            %rsp

  movdqa           (%rsp),                         %xmm12
  movdqa           0x10(%rsp),                     %xmm13
  movdqa           0x20(%rsp),                     %xmm14
  movdqa           0x30(%rsp),                     %xmm15

  mov              %rbp,                           %rsp

  pop              %rbp
  pop              %rbx
  ret



.globl gc_evaluate
gc_evaluate:

  push             %rbx
  push             %rbp
  mov              %rsp,                           %rbp

  and              $0xfffffffffffffff0,            %rsp

  sub              $64,                            %rsp
  movdqa           %xmm12,                         (%rsp)
  movdqa           %xmm13,                         0x10(%rsp)
  movdqa           %xmm14,                         0x20(%rsp)
  movdqa           %xmm15,                         0x30(%rsp)

  movdqa           %xmm0,                          delta

  movdqa           (fixed_aes_key),                sched0
  movdqa           0x010(fixed_aes_key),           sched1
  movdqa           0x020(fixed_aes_key),           sched2
  movdqa           0x030(fixed_aes_key),           sched3
  movdqa           0x040(fixed_aes_key),           sched4
  movdqa           0x050(fixed_aes_key),           sched5
  movdqa           0x060(fixed_aes_key),           sched6
  movdqa           0x070(fixed_aes_key),           sched7
  movdqa           0x080(fixed_aes_key),           sched8
  movdqa           0x090(fixed_aes_key),           sched9
  movdqa           0x0a0(fixed_aes_key),           sched10

  xor              %rbx,                           %rbx # index

gc_evaluate_start:
  mov              gate_type(gates),               gc_gate_type
  mov              gate_input0(gates),             input0_index
  mov              gate_input1(gates),             input1_index
  mov              gate_output(gates),             output_index
  add              $16,                            gates

  add              input0_index,                   input0_index
  add              input1_index,                   input1_index
  add              output_index,                   output_index

  lea              (wires,input0,8),               input0
  lea              (wires,input1,8),               input1
  lea              (wires,output,8),               output

#XOR_gate:
  movdqa           (input0),                       %xmm0
  cmp              $2,                             gc_gate_type #XOR
  jne              gc_evaluate_AND_gate

  pxor             (input1),                       %xmm0
  movdqa           %xmm0,                          (output)

  inc              index
  cmp              count,                          index
  jne              gc_evaluate_start
  jmp              gc_evaluate_finished

gc_evaluate_NOT_gate:
  movdqa           %xmm0,                          (output)

  inc              index
  cmp              count,                          index
  jne              gc_evaluate_start
  jmp              gc_evaluate_finished

gc_evaluate_AND_gate:
  cmp              $3,                             gc_gate_type # AND
  jne              gc_evaluate_NOT_gate

  movdqa           %xmm0,                          e1
  movdqa           (input1),                       e2

  psllq            $1,                             e1
  psllq            $1,                             e2

  movd	           index,                          %xmm0
  pxor             %xmm0,                          e1

  mov              index,                          %eax
  add              count,                          %eax
  movd	           %eax,                           %xmm0
  pxor             %xmm0,                          e2

  movdqa           e1,                             e3
  pxor             e2,                             e3

  pxor             sched0,                         e1
  pxor             sched0,                         e2

  aesenc           sched1,                         e1
  aesenc           sched1,                         e2

  aesenc           sched2,                         e1
  aesenc           sched2,                         e2

  aesenc           sched3,                         e1
  aesenc           sched3,                         e2

  aesenc           sched4,                         e1
  aesenc           sched4,                         e2

  aesenc           sched5,                         e1
  aesenc           sched5,                         e2

  aesenc           sched6,                         e1
  aesenc           sched6,                         e2

  aesenc           sched7,                         e1
  aesenc           sched7,                         e2

  aesenc           sched8,                         e1
  aesenc           sched8,                         e2

  aesenc           sched9,                         e1
  aesenc           sched9,                         e2

  aesenclast       sched10,                        e1
  aesenclast       sched10,                        e2

  pxor             e3,                             e1
  pxor             e2,                             e1

  testb            $1,                             (input0)
  jz               gc_evaluate_not_lsb_0
  pxor             (garbled),                      e1

gc_evaluate_not_lsb_0:
  add              $16,                            garbled
  testb            $1,                             (input1)
  jz               gc_evaluate_not_lsb_1

  pxor             (garbled),                      e1
  pxor             (input0),                       e1

gc_evaluate_not_lsb_1:
  add              $16,                            garbled
  movdqa           e1,                             (output)

  inc              index
  cmp              count,                          index
  jne              gc_evaluate_start

gc_evaluate_finished:

  movdqa           (%rsp),                         %xmm12
  movdqa           0x10(%rsp),                     %xmm13
  movdqa           0x20(%rsp),                     %xmm14
  movdqa           0x30(%rsp),                     %xmm15

  mov              %rbp,                           %rsp

  pop              %rbp
  pop              %rbx
  ret
