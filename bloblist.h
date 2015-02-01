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

#ifndef __LIBDECRYPT_BLOBLIST_H__
#define __LIBDECRYPT_BLOBLIST_H__

struct blob_list {
	unsigned char*    data;
	size_t            size;
	struct blob_list* next;
};

/**
 * libcurl-compatible callback function that writes to a struct blob_list.
 */
size_t blob_list_write_callback(void* chunk, size_t size, size_t nmemb,
		void* list_);

/**
 * Calculate the length of all data contained in \pelement.
 * \param  element  first element of struct blob_list
 * \return          number of bytes
 */
size_t blob_list_complete_length(struct blob_list* element);

/**
 * Create a consecutive block of data from a struct blob_list.
 * \param  out      bytestring to write data to
 * \param  element  first element of a struct blob_list
 */
void blob_list_to_block(char* out, struct blob_list* element);

#endif
