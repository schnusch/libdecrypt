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

#ifndef __LIBDECRYPT_DATA_H__
#define __LIBDECRYPT_DATA_H__

struct link_list {
	char*             url;
	size_t            url_len;
	char*             filename;
	size_t            filename_len;
	long long         filesize;
	struct link_list* next;
};

struct package_list {
	char*                name;
	size_t               name_len;
	char*                passwords;
	size_t               passwords_len;
	struct link_list*    links;
	struct package_list* next;
};

/**
 * Free all elements of a struct link_list recursively.
 * \param  element  first element of the struct link_list
 */
void free_link_list(struct link_list* element);

/**
 * Free all elements of a struct package_list recursively.
 * \param  element  first element of the struct package_list
 */
void free_package_list(struct package_list* element);

#endif
