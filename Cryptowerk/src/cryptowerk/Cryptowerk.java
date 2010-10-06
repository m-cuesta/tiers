/**

cryptowerk.Cryptowerk.java
Version: 1.0

********************************************************************************
Author:
Manuel Cuesta, programmer <camilocuesta@hotmail.com>

**************************************************

Cryptowerk is Copyright (c) 2010, Manuel Cuesta  <camilocuesta@hotmail.com >
All rights reserved.

Published under the terms of the new BSD license.
See: [http://github.com/m-cuesta/tiers] for the full license and other info.

LICENSE:

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

Neither the name of Manuel Cuesta nor the names of its contributors may be
used to endorse or promote products derived from this software without specific
prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.


**************************************************
Revision History / Change Log:

**************************************************
Notes:

*******************************************************************************/
package cryptowerk;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;


/** Encrypts and decrypts given an encryption key
 *
 * @author Manuel Camilo Cuesta
 */
public class Cryptowerk {

    /** The secret key for encription/decryption */
    private SecretKey secretKey;

    /** Provide a secret key you want to use for encryption.
     *  <br/><br/>
     *  Your messages will be encrypted with this key, and can only be decrypted
     *  with this key.
     *
     * @param pSecretKey
     */
    public Cryptowerk(SecretKey pSecretKey ) {
        secretKey = pSecretKey;
    }

    /** Encrypts the clear text given
     *
     * @param cleartext Text to be encrypted
     * @return The encrypted text, in a hex string representation
     * @throws UnsupportedEncodingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String encrypt( String cleartext) throws UnsupportedEncodingException, NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
        return toHexString( encrypt( toByteArray( cleartext ) ) );
    }

    /** Decrypts the given ciphered text
     *
     * @param ciphertext The text to be decrypted
     * @return The decrypted clear text
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public String decrypt( String ciphertext ) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
        return new String( decrypt( toByteArray(ciphertext) ));
    }

    /** Encrypts the clear text given
     * 
     * @param cleartext The clear text given must be in a byte array format
     * @return
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws UnsupportedEncodingException
     * @throws InvalidKeySpecException
     */
    public byte[] encrypt(byte[] cleartext) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnsupportedEncodingException, InvalidKeySpecException {

        byte[] ciphertext;
        Cipher desCipher;

        // Create the cipher
        desCipher = Cipher.getInstance("DESede");

        // Initialize the cipher for encryption
        desCipher.init(Cipher.ENCRYPT_MODE, secretKey );
        
        // Encrypt the cleartext
        ciphertext = desCipher.doFinal(cleartext);

        return ciphertext;

    }

    /** Decrypts the given ciphered text
     * 
     * @param ciphertext Encrypted text to be decrypted
     * @return The original clear text
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     */
    public byte[] decrypt( byte[] ciphertext ) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException  {

        byte[] cleartext;
        Cipher desCipher;

        // Create the cipher
        desCipher = Cipher.getInstance("DESede");

        // Initialize the cipher for decryption
        desCipher.init(Cipher.DECRYPT_MODE, secretKey );

        // Encrypt the cleartext
        cleartext = desCipher.doFinal(ciphertext);

        return cleartext;

    }

    /** Hex characters table, for converting byte arrays to readable hex strings
     *
     */
    private static final byte[] HEX_CHAR_TABLE = {
    (byte)'0', (byte)'1', (byte)'2', (byte)'3',
    (byte)'4', (byte)'5', (byte)'6', (byte)'7',
    (byte)'8', (byte)'9', (byte)'a', (byte)'b',
    (byte)'c', (byte)'d', (byte)'e', (byte)'f'
    };

    /** Converts a byte array to its hex string representation
     *
     * @param raw A byte array
     * @return Hex string
     * @throws UnsupportedEncodingException
     */
    public static String toHexString(byte[] raw)throws UnsupportedEncodingException
    {
      byte[] hex = new byte[2 * raw.length];
      int index = 0;
      for (byte b : raw)
      {
        int v = b & 0xFF;
        hex[index++] = HEX_CHAR_TABLE[v >> 4];
        hex[index++] = HEX_CHAR_TABLE[v & 0xF];
      }
      return new String(hex, "ASCII");
    }

    /** Converts a hex string to a byte array
     *
     * @param hex hex string
     * @return byte array representation of the hex string given
     */
    public static byte[] toByteArray(String hex)  {
      byte[] bts = new byte[hex.length() / 2];
      for (int i = 0; i < bts.length; i++)
      {
         bts[i] = (byte) Integer.parseInt(hex.substring(i*2, i*2+2), 16);
      }
      return bts;
    }

    /** Generates a secret key given a raw key as a byte array
     *
     * @param rawkey
     * @return
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws InvalidKeySpecException
     */
    public static SecretKey readKey(byte[] rawkey)
       throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException
    {
      DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);
      SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
      SecretKey key = keyfactory.generateSecret(keyspec);
      return key;
    }

    /** Encrypts a clear text into a MD5 hash
     *
     * @param cleartext
     * @return
     * @throws NoSuchAlgorithmException
     * @throws UnsupportedEncodingException
     */
    public static byte[] hashMD5(String cleartext ) throws NoSuchAlgorithmException, UnsupportedEncodingException {

        MessageDigest md = MessageDigest.getInstance("MD5");
        byte[] thedigest = md.digest( cleartext.getBytes("UTF-8") );
        return thedigest ;
    }

}
