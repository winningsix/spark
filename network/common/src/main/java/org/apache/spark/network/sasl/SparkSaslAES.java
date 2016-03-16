/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.spark.network.sasl;

import com.intel.chimera.cipher.Cipher;
import com.intel.chimera.cipher.CipherTransformation;
import com.intel.chimera.utils.Utils;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import javax.security.sasl.SaslException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Properties;

/**
 * AES encryption and decryption.
 */
public class SparkSaslAES {
  private static final byte[] EMPTY_BYTE_ARRAY = new byte[0];

  private final Cipher encryptor;
  private final Cipher decryptor;

  private final Integrity integrity;

  public SparkSaslAES(CipherTransformation cipherTransformation, Properties properties, byte[] inKey,
      byte[] outKey, byte[] inIv, byte[] outIv) throws IOException {
    checkTransformation(cipherTransformation);
    // encryptor
    encryptor = Utils.getCipherInstance(cipherTransformation, properties);
    try {
      encryptor.init(Cipher.ENCRYPT_MODE, outKey, outIv);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new IOException("Failed to initialize encryptor", e);
    }

    // decryptor
    decryptor = Utils.getCipherInstance(cipherTransformation, properties);
    try {
      decryptor.init(Cipher.DECRYPT_MODE, inKey, inIv);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new IOException("Failed to initialize decryptor", e);
    }

    integrity = new Integrity(outKey, inKey);
  }

  /**
   * Encrypts input data. The result composes of (msg, padding if needed, mac) and sequence num.
   * @param data the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new encrypted byte array.
   * @throws SaslException if error happens
   */
  public byte[] wrap(byte[] data, int offset, int len) throws SaslException {
    // mac
    byte[] mac = integrity.getHMAC(data, offset, len);
    integrity.incMySeqNum();

    // padding based on cipher
    byte[] padding;
    if (encryptor.getTransformation() == CipherTransformation.AES_CBC_NOPADDING) {
      int bs = encryptor.getTransformation().getAlgorithmBlockSize();
      int pad = bs - (len + 10) % bs;
      padding = new byte[pad];
      for (int i = 0; i < pad; i ++) {
        padding[i] = (byte) pad;
      }
    } else {
      padding = EMPTY_BYTE_ARRAY;
    }

    // encrypt
    byte[] encrypted = new byte[len + 10 + padding.length];
    try {
      int n = encryptor.update(data, offset, len, encrypted, 0);
      n += encryptor.update(padding, 0, padding.length, encrypted, n);
      encryptor.update(mac, 0, 10, encrypted, n);
    } catch (ShortBufferException sbe) {
      // this should not happen
      throw new SaslException("Error happens during encrypt data", sbe);
    }

    // append seqNum used for mac
    byte[] wrapped = new byte[encrypted.length + 4];
    System.arraycopy(encrypted, 0, wrapped, 0, encrypted.length);
    System.arraycopy(integrity.getSeqNum(), 0, wrapped, encrypted.length, 4);

    return wrapped;
  }

  /**
   * Decrypts input data. The input composes of (msg, padding if needed, mac) and sequence num.
   * The result is msg.
   * @param data the input byte array
   * @param offset the offset in input where the input starts
   * @param len the input length
   * @return the new decrypted byte array.
   * @throws SaslException if error happens
   */
  public byte[] unwrap(byte[] data, int offset, int len) throws SaslException {
    // get plaintext and seqNum
    byte[] decrypted = new byte[len - 4];
    byte[] peerSeqNum = new byte[4];
    try {
      decryptor.update(data, offset, len - 4, decrypted, 0);
    } catch (ShortBufferException sbe) {
      // this should not happen
      throw new SaslException("Error happens during decrypt data", sbe);
    }
    System.arraycopy(data, offset + decrypted.length, peerSeqNum, 0, 4);

    // get msg and mac
    byte[] msg = new byte[decrypted.length - 10];
    byte[] mac = new byte[10];
    System.arraycopy(decrypted, 0, msg, 0, msg.length);
    System.arraycopy(decrypted, msg.length, mac, 0, 10);

    // modify msg length if padding
    int msgLength = msg.length;
    if (decryptor.getTransformation() == CipherTransformation.AES_CBC_NOPADDING) {
      msgLength -= (int) msg[msgLength - 1];
    }

    // check mac integrity and msg sequence
    if (!integrity.compareHMAC(mac, peerSeqNum, msg, 0, msgLength)) {
      throw new SaslException("Unmatched MAC");
    }
    if (!integrity.comparePeerSeqNum(peerSeqNum)) {
      throw new SaslException("Out of order sequencing of messages. Got: " + integrity.byteToInt
          (peerSeqNum) + " Expected: " + integrity.peerSeqNum);
    }
    integrity.incPeerSeqNum();

    // return msg considering padding
    if (msgLength == msg.length) {
      return msg;
    } else {
      byte[] clearMsg = new byte[msgLength];
      System.arraycopy(msg, 0, clearMsg, 0, msgLength);
      return clearMsg;
    }
  }

  private void checkTransformation(CipherTransformation transformation) throws IOException {
    if (transformation == CipherTransformation.AES_CBC_NOPADDING
        || transformation == CipherTransformation.AES_CTR_NOPADDING) {
      return;
    }
    throw new IOException("AES cipher transformation is not supported: "
        + transformation.getName());
  }

  /**
   * Helper class for providing integrity protection.
   */
  private static class Integrity {

    private int mySeqNum = 0;
    private int peerSeqNum = 0;
    private byte[] seqNum = new byte[4];

    private byte[] myKey;
    private byte[] peerKey;

    Integrity(byte[] outKey, byte[] inKey) throws IOException {
      myKey = outKey;
      peerKey = inKey;
    }

    byte[] getHMAC(byte[] msg, int start, int len) throws SaslException {
      intToByte(mySeqNum);
      return calculateHMAC(myKey, seqNum, msg, start, len);
    }

    boolean compareHMAC(byte[] expectedHMAC, byte[] peerSeqNum, byte[] msg, int start,
        int len) throws SaslException {
      byte[] mac = calculateHMAC(peerKey, peerSeqNum, msg, start, len);
      return Arrays.equals(mac, expectedHMAC);
    }

    boolean comparePeerSeqNum(byte[] peerSeqNum) {
      return this.peerSeqNum == byteToInt(peerSeqNum);
    }

    byte[] getSeqNum() {
      return seqNum;
    }

    void incMySeqNum() {
      mySeqNum ++;
    }

    void incPeerSeqNum() {
      peerSeqNum ++;
    }

    private byte[] calculateHMAC(byte[] key, byte[] seqNum, byte[] msg, int start,
        int len) throws SaslException {
      byte[] seqAndMsg = new byte[4+len];
      System.arraycopy(seqNum, 0, seqAndMsg, 0, 4);
      System.arraycopy(msg, start, seqAndMsg, 4, len);

      try {
        SecretKey keyKi = new SecretKeySpec(key, "HmacMD5");
        Mac m = Mac.getInstance("HmacMD5");
        m.init(keyKi);
        m.update(seqAndMsg);
        byte[] hMAC_MD5 = m.doFinal();

        /* First 10 bytes of HMAC_MD5 digest */
        byte macBuffer[] = new byte[10];
        System.arraycopy(hMAC_MD5, 0, macBuffer, 0, 10);

        return macBuffer;
      } catch (InvalidKeyException e) {
        throw new SaslException("Invalid bytes used for key of HMAC-MD5 hash.", e);
      } catch (NoSuchAlgorithmException e) {
        throw new SaslException("Error creating instance of MD5 MAC algorithm", e);
      }
    }

    private void intToByte(int num) {
      for(int i = 3; i >= 0; i --) {
        seqNum[i] = (byte)(num & 0xff);
        num >>>= 8;
      }
    }

    private int byteToInt(byte[] seqNum) {
      int answer = 0;
      for (int i = 0; i < 4; i ++) {
        answer <<= 8;
        answer |= ((int)seqNum[i] & 0xff);
      }
      return answer;
    }
  }
}
