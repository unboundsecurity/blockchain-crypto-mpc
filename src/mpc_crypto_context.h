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
#include "mpc_crypto_share.h"
#include "mpc_crypto_message.h"

class mpc_crypto_context_t : public ub::convertable_t
{
public:
  mpc_crypto_context_t();
  virtual ~mpc_crypto_context_t() {}
  virtual void convert(ub::converter_t& converter) override;

  void get_info(mpc_crypto_context_info_t& info) const;

  virtual uint64_t get_type() const = 0;
  uint64_t get_uid() const { return uid; }
  uint64_t get_share_uid() const { return share_uid; }
  int get_peer() const { return peer; }
  void set_peer(int peer) { this->peer = peer; }
  void set_uid(uint64_t uid) { this->uid = uid; }
  void set_share_uid(uint64_t share_uid) { this->share_uid = share_uid; }

  virtual mpc_crypto_key_e get_share_type() const  = 0;
  
  virtual error_t step(const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags) = 0;
  virtual void set_share_core(const mpc_crypto_share_t& share) = 0;
  virtual error_t get_share(mpc_crypto_share_t*& share) const;

  virtual int get_messages_count() const = 0;
  virtual bool changes_share() const { return false; }

  int get_current_step() const { return current_step; }
  void set_next_step() { current_step++; }

  error_t set_share(const mpc_crypto_share_t& share);
  virtual void get_share_core(mpc_crypto_share_t& dst) const = 0;
  bool is_finished() const { return (current_step+1)*2 + ((peer==1) ? 0 : 1) > get_messages_count(); }
  virtual mpc_crypto_share_t* create_share() const = 0;


protected:
  static const uint64_t CODE_TYPE = 0x5829a79154354702;
  uint64_t uid;
  uint64_t share_uid;
  int peer; 
  int current_step;

  struct none_message_t 
  {
    void convert(ub::converter_t& converter) {}
  };

  typedef none_message_t message1_t;
  typedef none_message_t message2_t;
  typedef none_message_t message3_t;
  typedef none_message_t message4_t;
  typedef none_message_t message5_t;
  typedef none_message_t message6_t;
  typedef none_message_t message7_t;
  typedef none_message_t message8_t;
  typedef none_message_t message9_t;
  typedef none_message_t message10_t;
  typedef none_message_t message11_t;
  typedef none_message_t message12_t;
  typedef none_message_t message13_t;
  typedef none_message_t message14_t;
  typedef none_message_t message15_t;
  typedef none_message_t message16_t;
  typedef none_message_t message17_t;
  typedef none_message_t message18_t;
  typedef none_message_t message19_t;
  typedef none_message_t message20_t;
  typedef none_message_t message21_t;
  typedef none_message_t message22_t;
  typedef none_message_t message23_t;
  typedef none_message_t message24_t;
  typedef none_message_t message25_t;


  //error_t party1_step1(none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step1 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step2 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step2 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step3 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step3 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step4 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step4 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step5 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step5 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step6 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step6 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step7 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step7 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step8 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step8 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step9 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step9 (const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step10(const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step10(const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step11(const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step11(const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step12(const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step12(const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party1_step13(const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }
  error_t party2_step13(const none_message_t& in, none_message_t& out) { return ub::error(E_BADARG); }

  template<typename protocol_t> static error_t protocol_step(protocol_t& protocol, const mpc_crypto_message_t& in, mpc_crypto_message_t& out, unsigned& flags)
  {
    error_t rv = 0;
    int current_step = protocol.get_current_step();
    int peer = protocol.get_peer();

    flags = 0;
    int messages_count = protocol.get_messages_count();

    typename protocol_t::message1_t  msg1;
    typename protocol_t::message2_t  msg2;
    typename protocol_t::message3_t  msg3;
    typename protocol_t::message4_t  msg4;
    typename protocol_t::message5_t  msg5;
    typename protocol_t::message6_t  msg6;
    typename protocol_t::message7_t  msg7;
    typename protocol_t::message8_t  msg8;
    typename protocol_t::message9_t  msg9;
    typename protocol_t::message10_t msg10;
    typename protocol_t::message11_t msg11;
    typename protocol_t::message12_t msg12;
    typename protocol_t::message13_t msg13;
    typename protocol_t::message14_t msg14;
    typename protocol_t::message15_t msg15;
    typename protocol_t::message16_t msg16;
    typename protocol_t::message17_t msg17;
    typename protocol_t::message18_t msg18;
    typename protocol_t::message19_t msg19;
    typename protocol_t::message20_t msg20;
    typename protocol_t::message21_t msg21;
    typename protocol_t::message22_t msg22;
    typename protocol_t::message23_t msg23;
    typename protocol_t::message24_t msg24;
    typename protocol_t::message25_t msg25;

    if (peer==2 && current_step==0 && messages_count>=1)  
    {
      protocol.set_uid(in.get_context_uid());
      if (rv = in.get(protocol,  1,  1,  msg1)) return rv;
    }
    if (false);
    else if (peer==1 && current_step==1  && messages_count>=2)  { if (rv = in.get(protocol,  2,  2,  msg2))  return rv; }
    else if (peer==2 && current_step==1  && messages_count>=3)  { if (rv = in.get(protocol,  3,  1,  msg3))  return rv; }
    else if (peer==1 && current_step==2  && messages_count>=4)  { if (rv = in.get(protocol,  4,  2,  msg4))  return rv; }
    else if (peer==2 && current_step==2  && messages_count>=5)  { if (rv = in.get(protocol,  5,  1,  msg5))  return rv; }
    else if (peer==1 && current_step==3  && messages_count>=6)  { if (rv = in.get(protocol,  6,  2,  msg6))  return rv; }
    else if (peer==2 && current_step==3  && messages_count>=7)  { if (rv = in.get(protocol,  7,  1,  msg7))  return rv; }
    else if (peer==1 && current_step==4  && messages_count>=8)  { if (rv = in.get(protocol,  8,  2,  msg8))  return rv; }
    else if (peer==2 && current_step==4  && messages_count>=9)  { if (rv = in.get(protocol,  9,  1,  msg9))  return rv; }
    else if (peer==1 && current_step==5  && messages_count>=10) { if (rv = in.get(protocol, 10,  2,  msg10)) return rv; }
    else if (peer==2 && current_step==5  && messages_count>=11) { if (rv = in.get(protocol, 11,  1,  msg11)) return rv; }
    else if (peer==1 && current_step==6  && messages_count>=12) { if (rv = in.get(protocol, 12,  2,  msg12)) return rv; }
    else if (peer==2 && current_step==6  && messages_count>=13) { if (rv = in.get(protocol, 13,  1,  msg13)) return rv; }
    else if (peer==1 && current_step==7  && messages_count>=14) { if (rv = in.get(protocol, 14,  2,  msg14)) return rv; }
    else if (peer==2 && current_step==7  && messages_count>=15) { if (rv = in.get(protocol, 15,  1,  msg15)) return rv; }
    else if (peer==1 && current_step==8  && messages_count>=16) { if (rv = in.get(protocol, 16,  2,  msg16)) return rv; }
    else if (peer==2 && current_step==8  && messages_count>=17) { if (rv = in.get(protocol, 17,  1,  msg17)) return rv; }
    else if (peer==1 && current_step==9  && messages_count>=18) { if (rv = in.get(protocol, 18,  2,  msg18)) return rv; }
    else if (peer==2 && current_step==9  && messages_count>=19) { if (rv = in.get(protocol, 19,  1,  msg19)) return rv; }
    else if (peer==1 && current_step==10 && messages_count>=20) { if (rv = in.get(protocol, 20,  2,  msg20)) return rv; }
    else if (peer==2 && current_step==10 && messages_count>=21) { if (rv = in.get(protocol, 21,  1,  msg21)) return rv; }
    else if (peer==1 && current_step==10 && messages_count>=22) { if (rv = in.get(protocol, 22,  2,  msg22)) return rv; }
    else if (peer==2 && current_step==11 && messages_count>=23) { if (rv = in.get(protocol, 23,  1,  msg23)) return rv; }
    else if (peer==1 && current_step==11 && messages_count>=24) { if (rv = in.get(protocol, 24,  2,  msg24)) return rv; }
    else if (peer==2 && current_step==12 && messages_count>=25) { if (rv = in.get(protocol, 25,  1,  msg25)) return rv; }

    switch (current_step)
    {
      case 0:  rv = (peer==1) ? protocol.party1_step1 (msg1)         : protocol.party2_step1 (msg1,  msg2);  break;
      case 1:  rv = (peer==1) ? protocol.party1_step2 (msg2,  msg3)  : protocol.party2_step2 (msg3,  msg4);  break;
      case 2:  rv = (peer==1) ? protocol.party1_step3 (msg4,  msg5)  : protocol.party2_step3 (msg5,  msg6);  break;
      case 3:  rv = (peer==1) ? protocol.party1_step4 (msg6,  msg7)  : protocol.party2_step4 (msg7,  msg8);  break;
      case 4:  rv = (peer==1) ? protocol.party1_step5 (msg8,  msg9)  : protocol.party2_step5 (msg9,  msg10); break;
      case 5:  rv = (peer==1) ? protocol.party1_step6 (msg10, msg11) : protocol.party2_step6 (msg11, msg12); break;
      case 6:  rv = (peer==1) ? protocol.party1_step7 (msg12, msg13) : protocol.party2_step7 (msg13, msg14); break;
      case 7:  rv = (peer==1) ? protocol.party1_step8 (msg14, msg15) : protocol.party2_step8 (msg15, msg16); break;
      case 8:  rv = (peer==1) ? protocol.party1_step9 (msg16, msg17) : protocol.party2_step9 (msg17, msg18); break;
      case 9:  rv = (peer==1) ? protocol.party1_step10(msg18, msg19) : protocol.party2_step10(msg19, msg20); break;
      case 10: rv = (peer==1) ? protocol.party1_step11(msg20, msg21) : protocol.party2_step11(msg21, msg22); break;
      case 11: rv = (peer==1) ? protocol.party1_step12(msg22, msg23) : protocol.party2_step12(msg23, msg24); break;
      case 12: rv = (peer==1) ? protocol.party1_step13(msg24, msg25) : protocol.party2_step13(msg24, msg25); break;

      default: rv = ub::error(E_BADARG);
    }

    if (rv) return rv;
    messages_count = protocol.get_messages_count(); // can be changed after the step

    if (false);
    else if (peer==1 && current_step==0  && messages_count>=1)  out.set(protocol,   1, 2,  msg1);
    else if (peer==2 && current_step==0  && messages_count>=2)  out.set(protocol,   2, 1,  msg2);
    else if (peer==1 && current_step==1  && messages_count>=3)  out.set(protocol,   3, 2,  msg3);
    else if (peer==2 && current_step==1  && messages_count>=4)  out.set(protocol,   4, 1,  msg4);
    else if (peer==1 && current_step==2  && messages_count>=5)  out.set(protocol,   5, 2,  msg5);
    else if (peer==2 && current_step==2  && messages_count>=6)  out.set(protocol,   6, 1,  msg6);
    else if (peer==1 && current_step==3  && messages_count>=7)  out.set(protocol,   7, 2,  msg7);
    else if (peer==2 && current_step==3  && messages_count>=8)  out.set(protocol,   8, 1,  msg8);
    else if (peer==1 && current_step==4  && messages_count>=9)  out.set(protocol,   9, 2,  msg9);
    else if (peer==2 && current_step==4  && messages_count>=10) out.set(protocol,  10, 1, msg10);
    else if (peer==1 && current_step==5  && messages_count>=11) out.set(protocol,  11, 2, msg11);
    else if (peer==2 && current_step==5  && messages_count>=12) out.set(protocol,  12, 1, msg12);
    else if (peer==1 && current_step==6  && messages_count>=13) out.set(protocol,  13, 2, msg13);
    else if (peer==2 && current_step==6  && messages_count>=14) out.set(protocol,  14, 1, msg14);
    else if (peer==1 && current_step==7  && messages_count>=15) out.set(protocol,  15, 2, msg15);
    else if (peer==2 && current_step==7  && messages_count>=16) out.set(protocol,  16, 1, msg16);
    else if (peer==1 && current_step==8  && messages_count>=17) out.set(protocol,  17, 2, msg17);
    else if (peer==2 && current_step==8  && messages_count>=18) out.set(protocol,  18, 1, msg18);
    else if (peer==1 && current_step==9  && messages_count>=19) out.set(protocol,  19, 2, msg19);
    else if (peer==2 && current_step==9  && messages_count>=20) out.set(protocol,  20, 1, msg20);
    else if (peer==1 && current_step==10 && messages_count>=21) out.set(protocol,  21, 2, msg21);
    else if (peer==2 && current_step==10 && messages_count>=22) out.set(protocol,  22, 1, msg22);
    else if (peer==1 && current_step==11 && messages_count>=23) out.set(protocol,  23, 2, msg23);
    else if (peer==2 && current_step==11 && messages_count>=24) out.set(protocol,  24, 1, msg24);
    else if (peer==1 && current_step==12 && messages_count>=25) out.set(protocol,  25, 2, msg25);

    bool finished = protocol.is_finished();
    protocol.set_next_step();

    if (finished)
    {
      flags |= mpc_protocol_finished;
      if (protocol.changes_share()) flags |= mpc_share_changed;
    }
    return rv;
  }
};

template <class T> inline error_t mpc_crypto_message_t::get(const mpc_crypto_context_t& context, int message_type, int from, T& data) const
{
  error_t rv = 0;

  if (context.get_type() != context_type) return rv = ub::error(E_BADARG);
  if (context.get_peer() != dst_peer) return rv = ub::error(E_BADARG);
  if (context.get_share_uid() != share_uid) return rv = ub::error(E_BADARG);
  if (context.get_uid() != context_uid) return rv = ub::error(E_BADARG);
  if (this->message_type != message_type) return rv = ub::error(E_BADARG);

  if (!ub::convert(data, buffer)) return rv = ub::error(E_FORMAT);
  return rv;
}
