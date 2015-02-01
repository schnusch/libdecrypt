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

#ifndef __LIBDECRYPT_ENCODING_H__
#define __LIBDECRYPT_ENCODING_H__

/**
 * Calculate the value of a character in HEX notation.
 * \param  hex  character in question
 * \return      value of the character or 0xff if invalid
 */
unsigned char hex2int(char hex);

/**
 * Decodes a HEX encoded string.
 * \param  out     pointer to buffer that should contain the decoded bytestring
 *                 should be at least of length \pin_len / 2
 * \param  in      pointer to the encoded string
 * \param  in_len  length of \pin
 * \return         number of bytes written to \pout before an error occured or
 *                 0 if \pin_len is uneven
 */
size_t hex2bin(unsigned char* out, const char* in, size_t in_len);

/**
 * Calculate number of bytes needed to store decoded base64 string.
 * \param  in   base64 string in question
 * \param  len  length of the base64 string
 * \return      number of bytes needed to store decoded base64 string
 */
size_t base64_decode_length(const char* in, size_t len);

/**
 * Find first valid base64 substring in \pin.
 * \param  out      pointer to beginning of valid base64 substring
 * \param  in       string in question
 * \param  in_len   length of \pin
 * \return          length of base64 substring starting at \pout
 */
size_t base64_find(char** out, const char* in, size_t in_len);

/**
 * Decode a base64 string.
 * \param  out      pointer to buffer that should contain the decoded bytestring
 * \param  out_len  available length of output buffer
 * \param  in       base64 string in question
 * \param  in_len   length of the base64 string
 * \return          length of decoded bytestring
 */
int base64_decode(unsigned char* out, size_t out_len, const char* in, size_t in_len);

#endif
