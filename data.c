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

#include "data.h"

void free_link_list(struct link_list* element)
{
	if(element->url)
		free(element->url);
	if(element->filename)
		free(element->filename);
	if(element->next)
		free_link_list(element->next);
	free(element);
}

void free_package_list(struct package_list* element)
{
	if(element->name)
		free(element->name);
	if(element->passwords)
		free(element->passwords);
	if(element->links)
		free_link_list(element->links);
	if(element->next)
		free_package_list(element->next);
	free(element);
}
