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

package com.unboundTech.mpc;

import java.security.interfaces.RSAPublicKey;

public class Context implements AutoCloseable
{
  long handle = 0;

  private static final int MPC_PROTOCOL_FINISHED = 1;
  private static final int MPC_SHARE_CHANGED     = 2; // only sent w/finish

  public static class Info
  {
    public long UID = 0;
    public long shareUID = 0;
    public int peer = 0;
  }

  public static class MessageAndFlags implements AutoCloseable
  {
    public Message message = null;
    public boolean protocolFinished = false;
    public boolean shareChanged = false;

    @Override
    public void close() throws Exception
    {
      if (message!=null) message.close();
      message = null;
    }
  }

  @Override
  public void close()
  {
    if (handle!=0) Native.freeContext(handle);
    handle = 0;
  }

  public byte[] toBuf() throws MPCException
  {
    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.contextToBuf(handle, null, outLen));
    byte[] out = new byte[outLen.value];
    MPCException.check(Native.contextToBuf(handle, out, outLen));
    return out;
  }

  public static Context fromBuf(byte[] in) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.contextFromBuf(in, out));
    return out;
  }

  public Info getInfo() throws MPCException
  {
    Info out = new Info();
    MPCException.check(Native.contextInfo(handle, out));
    return out;
  }

  public MessageAndFlags step(Message in) throws MPCException
  {
    MessageAndFlags out = new MessageAndFlags();
    Message outMessage = new Message();
    Native.IntRef outFlags = new Native.IntRef();
    MPCException.check(Native.step(handle, (in==null) ? 0 : in.handle, outMessage, outFlags));
    if (outMessage.handle!=0) out.message = outMessage;
    if ((outFlags.value & MPC_PROTOCOL_FINISHED) != 0) out.protocolFinished = true;
    if ((outFlags.value & MPC_SHARE_CHANGED) != 0) out.shareChanged = true;
    return out;
  }

  public Share getShare() throws MPCException
  {
    Share out = new Share();
    MPCException.check(Native.getShare(handle, out));
    return out.handle==0 ? null : out;
  }

  public byte[] getResultEddsaSign() throws MPCException
  {
    byte[] out = new byte[64];
    MPCException.check(Native.getResultEddsaSign(handle, out));
    return out;
  }

  public static Context initGenerateEddsaKey(int peer) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initGenerateEddsaKey(peer, out));
    return out;
  }

  public byte[] getResultEcdsaSign() throws MPCException
  {
    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.getResultEcdsaSign(handle, null, outLen));
    byte[] out = new byte[outLen.value];
    MPCException.check(Native.getResultEcdsaSign(handle, out, outLen));
    return out;
  }

  public static Context initGenerateEcdsaKey(int peer) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initGenerateEcdsaKey(peer, out));
    return out;
  }

  public static Context initGenerateGenericSecret(int peer, int bits) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initGenerateGenericSecret(peer, bits, out));
    return out;
  }

  public static Context initImportGenericSecret(int peer, byte[] secret) throws MPCException
  {
    Context out = new Context();
    MPCException.check(Native.initImportGenericSecret(peer, secret, out));
    return out;
  }

  public Share getResultDeriveBIP32() throws MPCException
  {
    Share out = new Share();
    MPCException.check(Native.getResultDeriveBIP32(handle, out));
    return out;
  }

  public byte[] getResultBackupEcdsaKey() throws MPCException
  {
    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.getResultBackupEcdsaKey(handle, null, outLen));
    byte[] out = new byte[outLen.value];
    MPCException.check(Native.getResultBackupEcdsaKey(handle, out, outLen));
    return out;
  }

  public byte[] getResultBackupEddsaKey() throws MPCException
  {
    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.getResultBackupEddsaKey(handle, null, outLen));
    byte[] out = new byte[outLen.value];
    MPCException.check(Native.getResultBackupEddsaKey(handle, out, outLen));
    return out;
  }
}
