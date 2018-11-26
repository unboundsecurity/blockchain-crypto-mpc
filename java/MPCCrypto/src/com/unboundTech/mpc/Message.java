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

public class Message implements AutoCloseable
{
  long handle = 0;

  public static class Info
  {
    public long contextUID = 0;
    public long shareUID = 0;
    public int srcPeer = 0;
    public int dstPeer = 0;
  }

  @Override
  public void close()
  {
    if (handle!=0) Native.freeMessage(handle);
    handle = 0;
  }

  public byte[] toBuf() throws MPCException
  {
    Native.IntRef outLen = new Native.IntRef();
    MPCException.check(Native.messageToBuf(handle, null, outLen));
    byte[] out = new byte[outLen.value];
    MPCException.check(Native.messageToBuf(handle, out, outLen));
    return out;
  }

  public static Message fromBuf(byte[] in) throws MPCException
  {
    Message out = new Message();
    MPCException.check(Native.messageFromBuf(in, out));
    return out;
  }

  public Info getInfo() throws MPCException
  {
    Info out = new Info();
    MPCException.check(Native.messageInfo(handle, out));
    return out;
  }


}
