COMMENT @

NOTICE

The blockchain-crypto-mpc software is licensed under a proprietary license or the GPL v.3. 
If you choose to receive it under the GPL v.3 license, the following applies:
Blockchain-crypto-mpc is a Multiparty Computation (MPC)-based cryptographic library for securing blockchain wallets and applications.

Copyright (C) 2018, Unbound Tech Ltd. 

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

@

gate_t STRUCT
  gate_type     dd ?
  gate_input0   dd ?
  gate_input1   dd ?
  gate_output   dd ?
gate_t ENDS

sched0             equ xmm14
sched1             equ xmm1
sched2             equ xmm2
sched3             equ xmm3
sched4             equ xmm4
sched5             equ xmm5
sched6             equ xmm6
sched7             equ xmm7
sched8             equ xmm8
sched9             equ xmm9
sched10            equ xmm10
                  
e1                 equ xmm11
e2                 equ xmm12
e3                 equ xmm13
e4                 equ xmm14
delta              equ xmm15                 
                  
count              equ ecx
gates              equ rdx
garbled            equ r8
wires              equ r9

par_fixed_aes_key  equ 20h
par_delta_ptr      equ 28h

index              equ ebx
input0             equ rsi
input1             equ rdi
output             equ r10
fixed_aes_key      equ r11

input0_index       equ esi
input1_index       equ edi
output_index       equ r10d

gc_gate_type       equ eax

.code
 
gc_garble          PROC
 
  push             rsi
  push             rdi
  push             rbx
  push             rbp
  mov              rbp,                     rsp

  mov              fixed_aes_key,           par_fixed_aes_key[rbp+8*5]
  mov              rax,                     par_delta_ptr[rbp++8*5]
  movdqa           xmm0,                    [rax]

  and              rsp,                     0fffffffffffffff0h

  sub              rsp,                     160                                           
  movdqa           [rsp],                   xmm6  
  movdqa           [rsp+10h],               xmm7  
  movdqa           [rsp+20h],               xmm8  
  movdqa           [rsp+30h],               xmm9  
  movdqa           [rsp+40h],               xmm10  
  movdqa           [rsp+50h],               xmm11  
  movdqa           [rsp+60h],               xmm12  
  movdqa           [rsp+70h],               xmm13  
  movdqa           [rsp+80h],               xmm14  
  movdqa           [rsp+90h],               xmm15  

  movdqa           delta,                   xmm0
  sub              rsp,                     64
                                                                                       
  movdqa           sched1,                  [fixed_aes_key+0010h]
  movdqa           sched2,                  [fixed_aes_key+0020h]
  movdqa           sched3,                  [fixed_aes_key+0030h]
  movdqa           sched4,                  [fixed_aes_key+0040h]
  movdqa           sched5,                  [fixed_aes_key+0050h]
  movdqa           sched6,                  [fixed_aes_key+0060h]
  movdqa           sched7,                  [fixed_aes_key+0070h]
  movdqa           sched8,                  [fixed_aes_key+0080h]
  movdqa           sched9,                  [fixed_aes_key+0090h]
  movdqa           sched10,                 [fixed_aes_key+00a0h]

  xor              rbx,                     rbx                                   ; index
                                            
@start:                                     
  mov              gc_gate_type,            gate_t.gate_type[gates]
  mov              input0_index,            gate_t.gate_input0[gates] 
  mov              input1_index,            gate_t.gate_input1[gates] 
  mov              output_index,            gate_t.gate_output[gates] 
  add              gates,                   16

  add              input0_index,            input0_index
  add              input1_index,            input1_index
  add              output_index,            output_index
  
  lea              input0,                  [wires+input0*8]
  lea              input1,                  [wires+input1*8]
  lea              output,                  [wires+output*8]                                            

;@XOR_gate:                                                                             
  movdqa           xmm0,                    [input0]
  cmp              gc_gate_type,            2                               ; XOR
  jne              @AND_gate                

  pxor             xmm0,                    [input1]
  movdqa           [output],                xmm0

  inc              index                      
  cmp              index,                   count
  jne              @start
  jmp              @finished

@NOT_gate:                                  
  pxor             xmm0,                    delta
  movdqa           [output],                xmm0

  inc              index                      
  cmp              index,                   count                                     
  jne              @start
  jmp              @finished
                                                                                       
@AND_gate:                                  
  cmp              gc_gate_type,            3                               ; AND
  jne              @NOT_gate

  movdqa           e1,                      xmm0
  movdqa           e3,                      [input1]
  movdqa           e2,                      e1
  pxor             e2,                      delta
  movdqa           e4,                      e3
  pxor             e4,                      delta

  psllq            e1,                      1
  psllq            e2,                      1
  psllq            e3,                      1
  psllq            e4,                      1

  movd	           xmm0,                    index
  pxor             e1,                      xmm0
  pxor             e2,                      xmm0
                                            
  mov              eax,                     index
  add              eax,                     count
  movd	           xmm0,                    eax
  pxor             e3,                      xmm0
  pxor             e4,                      xmm0

  movdqa           xmm0,                    [fixed_aes_key]

  movdqa           [rsp],                   e1
  movdqa           [rsp+10h],               e2
  movdqa           [rsp+20h],               e3
  movdqa           [rsp+30h],               e4

  pxor             e1,                      xmm0
  pxor             e2,                      xmm0
  pxor             e3,                      xmm0
  pxor             e4,                      xmm0
                                            
  aesenc           e1,                      sched1
  aesenc           e2,                      sched1
  aesenc           e3,                      sched1
  aesenc           e4,                      sched1
                                            
  aesenc           e1,                      sched2
  aesenc           e2,                      sched2
  aesenc           e3,                      sched2
  aesenc           e4,                      sched2
                                            
  aesenc           e1,                      sched3
  aesenc           e2,                      sched3
  aesenc           e3,                      sched3
  aesenc           e4,                      sched3
                                            
  aesenc           e1,                      sched4
  aesenc           e2,                      sched4
  aesenc           e3,                      sched4
  aesenc           e4,                      sched4
                                            
  aesenc           e1,                      sched5
  aesenc           e2,                      sched5
  aesenc           e3,                      sched5
  aesenc           e4,                      sched5

  aesenc           e1,                      sched6
  aesenc           e2,                      sched6
  aesenc           e3,                      sched6
  aesenc           e4,                      sched6
                                            
  aesenc           e1,                      sched7
  aesenc           e2,                      sched7
  aesenc           e3,                      sched7
  aesenc           e4,                      sched7
                                            
  aesenc           e1,                      sched8
  aesenc           e2,                      sched8
  aesenc           e3,                      sched8
  aesenc           e4,                      sched8
                                            
  aesenc           e1,                      sched9 
  aesenc           e2,                      sched9
  aesenc           e3,                      sched9
  aesenc           e4,                      sched9
                                            
  aesenclast       e1,                      sched10
  aesenclast       e2,                      sched10
  aesenclast       e3,                      sched10
  aesenclast       e4,                      sched10
                                            
  pxor             e1,                      [rsp]
  pxor             e2,                      [rsp+10h]
  pxor             e3,                      [rsp+20h]
  pxor             e4,                      [rsp+30h]  
  
  movdqa           xmm0,                    e4                           ; x4=e4
                                              
  pxor             e2,                      e1
  pxor             e4,                      e3
  pxor             e4,                      [input0]                                                                 
                                            
  test             byte ptr [input1],       1
  jz               @not_lsb_1
  pxor             e2,                      delta
  movdqa           e3,                      xmm0

@not_lsb_1:                                            
  test             byte ptr [input0],       1
  jz               @not_lsb_0
  pxor             e1,                      e2                                           
                                            
@not_lsb_0:
  movdqa           [garbled],               e2
  add              garbled,                 16
  movdqa           [garbled],               e4
  add              garbled,                 16
                                            
  pxor             e1,                      e3
  movdqa           [output],                e1

  inc              index                      
  cmp              index,                   count
  jne              @start
                                            
@finished:                                            
  add              rsp,                     64

  movdqa           xmm6,                    [rsp]              
  movdqa           xmm7,                    [rsp+10h]          
  movdqa           xmm8,                    [rsp+20h]          
  movdqa           xmm9,                    [rsp+30h]          
  movdqa           xmm10,                   [rsp+40h]          
  movdqa           xmm11,                   [rsp+50h]  
  movdqa           xmm12,                   [rsp+60h]  
  movdqa           xmm13,                   [rsp+70h]  
  movdqa           xmm14,                   [rsp+80h]  
  movdqa           xmm15,                   [rsp+90h]  
;  add              rsp,                     160
  mov              rsp,                     rbp

  pop              rbp
  pop              rbx
  pop              rdi
  pop              rsi
  ret
 
gc_garble          ENDP
 
gc_evaluate        PROC
 
  push             rsi
  push             rdi
  push             rbx
  push             rbp
  mov              rbp,                     rsp

  mov              fixed_aes_key,           par_fixed_aes_key[rbp+8*5]
  mov              rax,                     par_delta_ptr[rbp++8*5]
  movdqa           xmm0,                    [rax]

  and              rsp,                     0fffffffffffffff0h

  sub              rsp,                     160                                           
  movdqa           [rsp],                   xmm6  
  movdqa           [rsp+10h],               xmm7  
  movdqa           [rsp+20h],               xmm8  
  movdqa           [rsp+30h],               xmm9  
  movdqa           [rsp+40h],               xmm10  
  movdqa           [rsp+50h],               xmm11  
  movdqa           [rsp+60h],               xmm12  
  movdqa           [rsp+70h],               xmm13  
  movdqa           [rsp+80h],               xmm14  
  movdqa           [rsp+90h],               xmm15  

  movdqa           delta,                   xmm0

  movdqa           sched0,                  [fixed_aes_key]                                                                  
  movdqa           sched1,                  [fixed_aes_key+0010h]
  movdqa           sched2,                  [fixed_aes_key+0020h]
  movdqa           sched3,                  [fixed_aes_key+0030h]
  movdqa           sched4,                  [fixed_aes_key+0040h]
  movdqa           sched5,                  [fixed_aes_key+0050h]
  movdqa           sched6,                  [fixed_aes_key+0060h]
  movdqa           sched7,                  [fixed_aes_key+0070h]
  movdqa           sched8,                  [fixed_aes_key+0080h]
  movdqa           sched9,                  [fixed_aes_key+0090h]
  movdqa           sched10,                 [fixed_aes_key+00a0h]

  xor              rbx,                     rbx                                   ; index
                                            
@start:                                     
  mov              gc_gate_type,            gate_t.gate_type[gates]
  mov              input0_index,            gate_t.gate_input0[gates] 
  mov              input1_index,            gate_t.gate_input1[gates] 
  mov              output_index,            gate_t.gate_output[gates] 
  add              gates,                   16

  add              input0_index,            input0_index
  add              input1_index,            input1_index
  add              output_index,            output_index
  
  lea              input0,                  [wires+input0*8]
  lea              input1,                  [wires+input1*8]
  lea              output,                  [wires+output*8]                                            

;@XOR_gate:                                                                             
  movdqa           xmm0,                    [input0]
  cmp              gc_gate_type,            2                               ; XOR
  jne              @AND_gate                

  pxor             xmm0,                    [input1]
  movdqa           [output],                xmm0

  inc              index                      
  cmp              index,                   count
  jne              @start
  jmp              @finished

@NOT_gate:                                  
  movdqa           [output],                xmm0

  inc              index                      
  cmp              index,                   count                                     
  jne              @start
  jmp              @finished
                                                                                       
@AND_gate:                                  
  cmp              gc_gate_type,            3                               ; AND
  jne              @NOT_gate

  movdqa           e1,                      xmm0
  movdqa           e2,                      [input1]

  psllq            e1,                      1
  psllq            e2,                      1

  movd	           xmm0,                    index
  pxor             e1,                      xmm0
                                            
  mov              eax,                     index
  add              eax,                     count
  movd	           xmm0,                    eax
  pxor             e2,                      xmm0

  movdqa           e3,                      e1
  pxor             e3,                      e2

  pxor             e1,                      sched0
  pxor             e2,                      sched0
                                            
  aesenc           e1,                      sched1
  aesenc           e2,                      sched1
                                            
  aesenc           e1,                      sched2
  aesenc           e2,                      sched2
                                            
  aesenc           e1,                      sched3
  aesenc           e2,                      sched3
                                            
  aesenc           e1,                      sched4
  aesenc           e2,                      sched4
                                            
  aesenc           e1,                      sched5
  aesenc           e2,                      sched5

  aesenc           e1,                      sched6
  aesenc           e2,                      sched6
                                            
  aesenc           e1,                      sched7
  aesenc           e2,                      sched7
                                            
  aesenc           e1,                      sched8
  aesenc           e2,                      sched8
                                            
  aesenc           e1,                      sched9 
  aesenc           e2,                      sched9
                                            
  aesenclast       e1,                      sched10
  aesenclast       e2,                      sched10
                                            
  pxor             e1,                      e3
  pxor             e1,                      e2
  
  test             byte ptr [input1],       1
  jz               @not_lsb_1

  pxor             e1,                      [garbled+16]
  pxor             e1,                      [input0]

@not_lsb_1:                                            
  test             byte ptr [input0],       1
  jz               @not_lsb_0
  pxor             e1,                      [garbled]                                 
                                            
@not_lsb_0:
  add              garbled,                 32
  movdqa           [output],                e1

  inc              index                      
  cmp              index,                   count
  jne              @start
                                            
@finished:                                            
  movdqa           xmm6,                    [rsp]              
  movdqa           xmm7,                    [rsp+10h]          
  movdqa           xmm8,                    [rsp+20h]          
  movdqa           xmm9,                    [rsp+30h]          
  movdqa           xmm10,                   [rsp+40h]          
  movdqa           xmm11,                   [rsp+50h]  
  movdqa           xmm12,                   [rsp+60h]  
  movdqa           xmm13,                   [rsp+70h]  
  movdqa           xmm14,                   [rsp+80h]  
  movdqa           xmm15,                   [rsp+90h]  
;  add              rsp,                     160
  mov              rsp,                     rbp

  pop              rbp
  pop              rbx
  pop              rdi
  pop              rsi
  ret
 
gc_evaluate        ENDP

END
