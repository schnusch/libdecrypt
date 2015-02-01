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

#include <openssl/conf.h>
#include <stdio.h>

#include "crypto.h"

size_t openssl_evp_crypt(
		int (*crypt_init)  (EVP_CIPHER_CTX*, const EVP_CIPHER*, ENGINE*, const unsigned char*, const unsigned char*),
		int (*crypt_update)(EVP_CIPHER_CTX*, unsigned char*, int*, const unsigned char*, int),
		int (*crypt_final) (EVP_CIPHER_CTX*, unsigned char*, int*),
		unsigned char* out, const unsigned char* in, size_t in_len,
		const EVP_CIPHER* type, const unsigned char* key,
		const unsigned char* iv, int padding)
{
	OPENSSL_config(NULL);
	OpenSSL_add_all_algorithms();

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if(!ctx)
	{
		fprintf(stderr, "CTX_new failed.\n");
		goto error;
	}

	if(crypt_init(ctx, type, NULL, key, iv) != 1)
	{
		fprintf(stderr, "Initialization failed.\n");
		goto error;
	}
	EVP_CIPHER_CTX_set_padding(ctx, padding);

	size_t out_len = 0;
	while(in_len >= (size_t)EVP_CIPHER_CTX_block_size(ctx))
	{
		int tmp_len;
		if(crypt_update(ctx, out + out_len, &tmp_len, in, in_len) != 1)
		{
			fprintf(stderr, "Update failed.\n");
			goto error;
		}
		in_len  -= tmp_len;
		out_len += tmp_len;
	}

	if(in_len > 0)
	{
		int tmp_len;
		if(crypt_final(ctx, out + out_len, &tmp_len) != 1)
		{
			fprintf(stderr, "Final failed.\n");
			goto error;
		}
		in_len  -= tmp_len;
		out_len += tmp_len;
	}

	goto fin;
error:
	out_len = 0;
fin:
	EVP_CIPHER_CTX_free(ctx);
	return out_len;
}

size_t openssl_evp_encrypt(unsigned char* out, const unsigned char* in,
		size_t in_len, const EVP_CIPHER* type, const unsigned char* key,
		const unsigned char* iv, int padding)
{
	return openssl_evp_crypt(EVP_EncryptInit_ex, EVP_EncryptUpdate,
			EVP_EncryptFinal_ex, out, in, in_len, type, key, iv, padding);
}

size_t openssl_evp_decrypt(unsigned char* out, const unsigned char* in,
		size_t in_len, const EVP_CIPHER* type, const unsigned char* key,
		const unsigned char* iv, int padding)
{
	return openssl_evp_crypt(EVP_DecryptInit_ex, EVP_DecryptUpdate,
			EVP_DecryptFinal_ex, out, in, in_len, type, key, iv, padding);
}
