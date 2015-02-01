/* Copyright (C) 2015 Schnusch

   This file is part of libdecrypt.

   libdecrypt is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   libdecrypt is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with libdecrypt.  If not, see <http://www.gnu.org/licenses/>. */

#ifndef __LIBDECRYPT_CRYPTO_H__
#define __LIBDECRYPT_CRYPTO_H__

#include <openssl/evp.h>

#define EVP_aes_192_cfb8_iv_length 16
#define EVP_aes_128_key_length     16

/**
 * Calculate the value of a character in HEX notation.
 * \param  out      pointer to buffer that should contain the encrypted
 *                  bytestring
 * \param  in       pointer to plaintext bytestring
 * \param  in_len   length of the bytestring \pout as well as \pin
 * \param  type     encryption method to use
 * \param  key      bytestring containing the encryption key (should be at least
 *                  EVP_CIPHER_CTX_key_length(\ptype) bytes long
 * \param  iv       bytestring containing the initialization vector (should be
 *                  at least EVP_CIPHER_CTX_iv_length(\ptype) bytes long
 * \param  padding  enable padding
 * \return          number of bytes written to \pout
 */
size_t openssl_evp_encrypt(unsigned char* out, const unsigned char* in,
		size_t in_len, const EVP_CIPHER* type, const unsigned char* key,
		const unsigned char* iv, int padding);

/**
 * Calculate the value of a character in HEX notation.
 * \param  out      pointer to buffer that should contain the decrypted
 *                  bytestring
 * \param  in       pointer to encrypted bytestring
 * \param  in_len   length of the bytestring \pout as well as \pin
 * \param  type     decryption method to use
 * \param  key      bytestring containing the decryption key (should be at least
 *                  EVP_CIPHER_CTX_key_length(\ptype) bytes long
 * \param  iv       bytestring containing the initialization vector (should be
 *                  at least EVP_CIPHER_CTX_iv_length(\ptype) bytes long
 * \param  padding  enable padding
 * \return          number of bytes written to \pout
 */
size_t openssl_evp_decrypt(unsigned char* out, const unsigned char* in,
		size_t in_len, const EVP_CIPHER* type, const unsigned char* key,
		const unsigned char* iv, int padding);

#endif
