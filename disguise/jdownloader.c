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
#include <string.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <stdio.h>

#include "disguise.h"
#include "../dlc.h"
#include "../encoding.h"
#include "../crypto.h"

#define JDOWNLOADER_REVISION "9.581"
#define DLC_API_QUERY_URL    "http://service.jdownloader.org/dlcrypt/service.php"
#define DLC_API_QUERY_DATA   "destType=jdtc5&b=last09&p=2009&srcType=dlc&data=%s&v=" JDOWNLOADER_REVISION
#define DLC_API_HEADER_NUM   9
const char* DLC_API_HEADERS[DLC_API_HEADER_NUM] = {
		"User-Agent: Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.10) Gecko/2009042523 Ubuntu/9.04 (jaunty) Firefox/3.0.10",
		"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
		"Accept-Language: de, en-gb;q=0.9, en;q=0.8",
		"Accept-Encoding: gzip",
		"Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7",
		"Cache-Control: no-cache",
		"Pragma: no-cache",
		"Connection: close",
		"rev: " JDOWNLOADER_REVISION};
#define DLC_API_RESPONSE_RC_START "<rc>"
#define DLC_API_RESPONSE_RC_END   "</rc>"

struct i_want_to_be_freed {
	struct curl_slist* headers;
	char*              data;
};

void* dlc_api_curl_custom(CURL* curl, const char dlc_id[DLC_ID_LENGTH])
{
	// headers
	struct curl_slist* headers = NULL;
	for(size_t i = 0; i < DLC_API_HEADER_NUM; i++)
		headers = curl_slist_append(headers, DLC_API_HEADERS[i]);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	// url
	curl_easy_setopt(curl, CURLOPT_URL, DLC_API_QUERY_URL);
	// data
	size_t data_len = strlen(DLC_API_QUERY_DATA) - 2 + strlen(dlc_id) + 1;
	char*  data     = malloc(data_len);
	snprintf(data, data_len, DLC_API_QUERY_DATA JDOWNLOADER_REVISION, dlc_id);
	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	// return
	struct i_want_to_be_freed* ret = malloc(sizeof(*ret));
	ret->headers = headers;
	ret->data    = data;
	return ret;
}

void dlc_api_curl_free(void* stuff_)
{
	struct i_want_to_be_freed* stuff = (struct i_want_to_be_freed*)stuff_;
	curl_slist_free_all(stuff->headers);
	free(stuff->data);
	free(stuff);
}

size_t get_decryption_key(unsigned char* decryption_key, size_t out_len,
		const char* data, size_t len)
{
	// parse API response
	size_t rc_offset = 0;
	for(size_t i = 0; i < len - strlen(DLC_API_RESPONSE_RC_START); i++)
		if(strncmp((char*)data + i, DLC_API_RESPONSE_RC_START,
				strlen(DLC_API_RESPONSE_RC_START)) == 0)
		{
			rc_offset = i + strlen(DLC_API_RESPONSE_RC_START);
			break;
		}
	size_t rc_len = len - rc_offset - strlen(DLC_API_RESPONSE_RC_END);
	for(size_t i = 0; i < len - rc_offset - strlen(DLC_API_RESPONSE_RC_END); i++)
		if(strncmp((char*)data + rc_offset + i, DLC_API_RESPONSE_RC_END,
				strlen(DLC_API_RESPONSE_RC_END)) == 0)
		{
			rc_len = i;
			break;
		}
	// decode rc
	char*  untouched_rc;
	size_t untouched_rc_len = base64_find(&untouched_rc, (char*)data + rc_offset,
			rc_len);
	size_t encrypted_rc_len = base64_decode_length(untouched_rc, untouched_rc_len);
	unsigned char* workspace = malloc(encrypted_rc_len);
	if(workspace)
	{
		base64_decode(workspace, encrypted_rc_len, untouched_rc, untouched_rc_len);
		// decrypt rc
		static const unsigned char key[] = {0xeb, 0xda, 0x23, 0x7a, 0x3d, 0x87,
				0xac, 0xcc, 0xf7, 0x2d, 0xcb, 0x61, 0x57, 0xfe, 0xe3, 0x14};
		openssl_evp_decrypt(workspace, workspace, encrypted_rc_len,
				EVP_aes_128_ecb(), key, NULL, 0);
		// decode rc
		char*  decrypted_rc;
		size_t decrypted_rc_len = base64_find(&decrypted_rc, (char*)workspace,
				encrypted_rc_len);
		size_t decoded_rc_len = base64_decode_length(decrypted_rc, decrypted_rc_len);
		base64_decode(workspace, decoded_rc_len, decrypted_rc, decrypted_rc_len);
		// finalization
		if(decoded_rc_len > out_len)
			decoded_rc_len = out_len;
		memcpy(decryption_key, workspace, decoded_rc_len);
		free(workspace);
		return decoded_rc_len;
	}
	else
		return 0;
}
