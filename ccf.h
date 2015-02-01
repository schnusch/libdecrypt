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

#ifndef __LIBDECRYPT_CCF_H__
#define __LIBDECRYPT_CCF_H__

#include "data.h"

/**
 * Decode a CCF container.
 * \param  data  pointer to a bytestring containing the content of the RSDF file
 * \param  size  size of \pdata
 * \return       a pointer to the first element of a struct link_list containing
 *               the decrypted links
 */
struct package_list* decrypt_ccf(const unsigned char* data, size_t size);

#endif
