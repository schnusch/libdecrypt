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

#ifndef __LIBDECRYPT_DISGUISE_H__
#define __LIBDECRYPT_DISGUISE_H__

#include <curl/curl.h>

/**
 * Modifies a curl request to look like JDownloader.
 * \param  curl    curl request object
 * \param  dlc_id  DLC ID
 * \return         pointer that must be passed to dlc_api_curl_free after the
 *                 execution of the curl request \pcurl
 */
void* dlc_api_curl_custom(CURL* curl, const char* dlc_id);

/**
 * Cleans up after an executed curl request modifed with dlc_api_curl_custom.
 * \param  stuff  pointer returned by dlc_api_curl_custom
 */
void dlc_api_curl_free(void* stuff);

/**
 * Parses the response of the DLC API and extract the decryption key.
 * \param  decryption_key  bytestring to store the key for the decryption of the
 *                         DLC file's contents
 * \param  out_len         size of \pdecryption_key
 * \param  data            response of the curl request
 * \param  len             size of \pdata
 * \return                 bytes written to \pdecryption_key
 */
size_t get_decryption_key(unsigned char* decryption_key, size_t out_len,
		const char* data, size_t len);

#endif
