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

#include <stdio.h>
#include <stdlib.h>

#include "../rsdf.h"
#include "../ccf.h"
#include "../dlc.h"

void print_link_list(struct link_list* links, const char* indent)
{
	for(struct link_list* link = links; link; link = link->next)
	{
		fputs(indent, stdout);
		printf("URL:  %s\n", link->url);
		if(link->filename_len > 0 && link->filename)
		{
			fputs(indent, stdout);
			printf("Name: %s\n", link->filename);
		}
		fputs(indent, stdout);
		printf("Size: %lld\n", link->filesize);
	}
}

void print_package_list(struct package_list* packages)
{
	for(struct package_list* package = packages; package; package = package->next)
	{
		printf("Name:     %s\n", package->name);
		if(package->passwords)
			printf("Password: \"%s\"\n", package->passwords);
		print_link_list(packages->links, "\t");
	}
}

void rsdf_demo(const char* file)
{
	FILE* fp = fopen(file, "r");
	fseek(fp, 0, SEEK_END);
	size_t len = ftell(fp);
	char* data = malloc(len);
	fseek(fp, 0, SEEK_SET);
	fread(data, 1, len, fp);
	fclose(fp);
	struct link_list* links = decrypt_rsdf(data, len);
	free(data);
	print_link_list(links, "");
	free_link_list(links);
}

void ccf_demo(const char* file)
{
	FILE* fp = fopen(file, "r");
	fseek(fp, 0, SEEK_END);
	size_t len = ftell(fp);
	unsigned char* data = malloc(len);
	fseek(fp, 0, SEEK_SET);
	fread(data, 1, len, fp);
	fclose(fp);
	struct package_list* packages = decrypt_ccf(data, len);
	free(data);
	print_package_list(packages);
	free_package_list(packages);
}

void dlc_demo(const char* file)
{
	FILE* fp = fopen(file, "r");
	fseek(fp, 0, SEEK_END);
	size_t len = ftell(fp);
	char* data = malloc(len);
	fseek(fp, 0, SEEK_SET);
	fread(data, 1, len, fp);
	fclose(fp);
	struct package_list* packages = decrypt_dlc(data, len);
	free(data);
	print_package_list(packages);
	free_package_list(packages);
}

int main(void)
{
	// RSDF
	fputs("RSDF:\n=====\n", stdout);
	rsdf_demo("test.rsdf");
	// CCF
	fputs("\nCCF:\n====\n", stdout);
	ccf_demo("test.ccf");
	// DLC
	fputs("\nDLC:\n====\n", stdout);
	dlc_demo("test.dlc");

	return 0;
}
