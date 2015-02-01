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

#include "bloblist.h"

size_t blob_list_write_callback(void* chunk, size_t size, size_t nmemb,
		void* list_)
{
	struct blob_list* element = (struct blob_list*)list_;
	for(; element->size != 0 && element->next; element = element->next);
	if(element->size != 0)
	{
		element->next = malloc(sizeof(*element));
		element = element->next;
	}
	element->next = NULL;
	element->size = size * nmemb;
	element->data = malloc(element->size);
	memcpy(element->data, chunk, element->size);
	return element->size;
}

size_t blob_list_complete_length(struct blob_list* element)
{
	if(element->next)
		return element->size + blob_list_complete_length(element->next);
	else
		return element->size;
}

void blob_list_to_block(char* out, struct blob_list* element)
{
	memcpy(out, element->data, element->size);
	free(element->data);
	if(element->next)
		blob_list_to_block(out + element->size, element->next);
	free(element);
}
