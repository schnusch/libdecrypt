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

#ifndef __LIBDECRYPT_DLC_H__
#define __LIBDECRYPT_DLC_H__

#include "data.h"

#define DLC_ID_LENGTH 88

/**
 * Decrypt a DLC container.
 * \param  data  pointer to a bytestring containing the content of the DLC file
 * \param  size  length of bytesting \pdata
 * \return       a pointer to the first element of a struct package_list containing
 *               the decrypted links
 */
struct package_list* decrypt_dlc(const char* data, size_t size);

#endif
