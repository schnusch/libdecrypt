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

#include <openssl/bio.h>
#include <openssl/evp.h>

#include "encoding.h"

#define IS_BASE64_CHARACTER(c) (('A' <= c && c <= 'Z') ||  ('a' <= c && c <= 'z') || ('0' <= c && c <= '9') || c == '+' || c == '/')

unsigned char hex2int(char hex)
{
	if(hex >= '0' && hex <= '9')
		return hex - '0';
	else if(hex >= 'A' && hex <= 'F')
		return hex - 'A' + 10;
	else if(hex >= 'a' && hex <= 'f')
		return hex - 'a' + 10;
	else
		return 0xff;
}

size_t hex2bin(unsigned char* out, const char* in, size_t in_len)
{
	size_t out_len = in_len / 2;
	for(size_t i = 0; i < out_len; i++)
	{
		unsigned char value = 0x00;
		for(size_t j = 0; j < 2; j++)
		{
			unsigned char tmp = hex2int(in[i * 2 + j]);
			if(tmp == 0xff)
				return i;
			value |= tmp << ((1 - j) * 4);
		}
		out[i] = value;
	}
	return out_len;
}

size_t base64_decode_length(const char* in, size_t len)
{
	size_t result = len / 4 * 3;
	for(size_t i = 1; i <= 2; i++)
	{
		if(len >= i && in[len - i] == '=')
			result--;
		else
			break;
	}
	return result;
}

size_t base64_find(char** out, const char* in, size_t in_len)
{
	size_t start = 0;
	// strip all leading non-base64 symbols
	for(; start < in_len && !IS_BASE64_CHARACTER(in[start]); start++);
	for(; start < in_len; start++)
	{
		size_t out_len = 0;
		for(size_t i = start; i < in_len; i++)
			if(IS_BASE64_CHARACTER(in[i]))
				out_len++;
			else
				break;
		size_t missing = 4 - out_len % 4;
		// trailing equal signs
		if(missing <= 2)
		{
			for(size_t i = 0; i < missing; i++)
				if(in[start + out_len] == '=')
					out_len++;
				else
					break;
			missing = out_len % 4;
			if(missing)
				out_len -= missing;
		}
		if(out_len >= 4 && out_len % 4 == 0)
		{
			*out = (char*)in + start;
			return out_len;
		}
	}
	*out = NULL;
	return 0;
}

int base64_decode(unsigned char* out, size_t out_len, const char* in, size_t in_len)
{
	BIO *b64  = BIO_new(BIO_f_base64());
	BIO *bmem = BIO_new_mem_buf((void*)in, in_len);
	bmem = BIO_push(b64, bmem);
	BIO_set_flags(bmem, BIO_FLAGS_BASE64_NO_NL);
	int ret = BIO_read(bmem, out, out_len);
	BIO_free_all(bmem);
	return ret;
}
