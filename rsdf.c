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

#include <stdlib.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <string.h>

#include "encoding.h"
#include "crypto.h"
#include "rsdf.h"

const unsigned char key[] = {
		0x8c, 0x35, 0x19, 0x2d, 0x96, 0x4d, 0xc3, 0x18, 0x2c, 0x6f, 0x84, 0xf3,
		0x25, 0x22, 0x39, 0xeb, 0x4a, 0x32, 0x0d, 0x25, 0x00, 0x00, 0x00, 0x00};
const unsigned char first_iv[EVP_aes_192_cfb8_iv_length] = {
		0xa3, 0xd5, 0xa3, 0x3c, 0xb9, 0x5a, 0xc1, 0xf5, 0xcb, 0xdb, 0x1a, 0xd2,
		0x5c, 0xb0, 0xa7, 0xaa};

int get_iv(unsigned char iv[EVP_aes_192_cfb8_iv_length])
{
/*	const unsigned char pre_iv[EVP_aes_192_cfb8_iv_length] = {
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
			0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	return openssl_evp_encrypt(iv, (unsigned char*)pre_iv,
			EVP_aes_192_cfb8_iv_length, EVP_aes_192_ecb(), key, NULL, 0);
*/	memcpy(iv, first_iv, EVP_aes_192_cfb8_iv_length);
	return EVP_aes_192_cfb8_iv_length;
}

bool is_split_char(unsigned char c)
{
	size_t length = 3;
	unsigned char split_chars[] = {'\n', '\r', 0xda};
	for(size_t i = 0; i < length; i++)
		if(c == split_chars[i])
			return true;
	return false;
}

char* decrypt_link(size_t* out_len, const unsigned char* in, size_t len,
		unsigned char iv[EVP_aes_192_cfb8_iv_length])
{
	// base64 decode
	int enc_len = base64_decode_length((char*)in, len);
	unsigned char* enc_link = malloc(enc_len);
	base64_decode(enc_link, enc_len, (char*)in, len);
	// decrypt
	char* out = malloc((enc_len + 1) * sizeof(*out));
	openssl_evp_decrypt((unsigned char*)out, enc_link, enc_len,
			EVP_aes_192_cfb8(), key, iv, 0);
	out[enc_len] = '\0';
	// set IV for decryption of the next link
	if(enc_len >= EVP_aes_192_cfb8_iv_length)
		memcpy(iv, enc_link + enc_len - EVP_aes_192_cfb8_iv_length,
				EVP_aes_192_cfb8_iv_length);
	else
	{
		size_t keep_length = EVP_aes_192_cfb8_iv_length - enc_len;
		memmove(iv,              iv + enc_len, keep_length);
		memcpy(iv + keep_length, enc_link,     enc_len);
	}
	free(enc_link);

	*out_len = enc_len + 1;
	return out;
}

struct link_list* decrypt_rsdf(const char* hex_data, size_t hex_len)
{
	// dehex
	size_t len = hex_len / 2;
	if(hex_len % 2)
		return NULL;
	unsigned char* data = malloc(len);
	hex2bin(data, hex_data, hex_len);
	// count lines
	size_t lines = 0;
	size_t line_begin = 0;
	for(size_t i = 0; i < len; i++)
		if(is_split_char(data[i]))
		{
			if(line_begin != i)
				lines += 1;
			line_begin = i + 1;
		}
	// parse lines
	unsigned char iv[EVP_aes_192_cfb8_iv_length];
	get_iv(iv);
	size_t line = 0;
	line_begin = 0;
	struct link_list* first = NULL;
	struct link_list* link;
	for(size_t i = 0; i < len; i++)
		if(is_split_char(data[i]))
		{
			if(line_begin != i)
			{
				if(first)
				{
					link->next = malloc(sizeof(*link));
					link = link->next;
				}
				else
				{
					first = malloc(sizeof(*link));
					link = first;
				}
				link->url = decrypt_link(&link->url_len, data + line_begin,
						i - line_begin, iv);
				// JDownloader: "CCF:"  -> " CCF: "
				// pyLoad:      "CCF: " -> ""
				link->filename     = NULL;
				link->filename_len = 0;
				link->filesize     = 0;
				line++;
			}
			line_begin = i + 1;
		}
	if(first)
		link->next = NULL;
	// clean-up
	free(data);
	return first;
}
