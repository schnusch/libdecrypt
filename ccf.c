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
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/evp.h>
#include <libxml/parser.h>

#include "ccf.h"
#include "crypto.h"

/**
 * Rotate a 32-bit integer by \pshift bits to the left.
 * \param  i      integer to rotate
 * \param  shift  number of bits to rotate by
 * \return        rotated integer
 */
uint32_t rotate_left(uint32_t i, uint8_t shift)
{
	return i << shift | i >> (sizeof(i) * 8 - shift);
}

/**
 * Rotate a 32-bit integer by \pshift bits to the right.
 * \param  i      integer to rotate
 * \param  shift  number of bits to rotate by
 * \return        rotated integer
 */
uint32_t rotate_right(uint32_t i, uint8_t shift)
{
	return i >> shift | i << (sizeof(i) * 8 - shift);
}

/**
 * Swap bytes in a consecutive square matrix along the main diagonal.
 * \param  block   byte matrix
 * \param  width   width of the matrix
 * \param  height  height of the matrix
 */
void swap_bytes_by_main_diagonal(unsigned char* block, size_t width, size_t height)
{
	height -= 1;
	for(size_t y = 0; y < height; y++)
		for(size_t x = y + 1; x < width; x++)
		{
			unsigned char buffer = block[y * 8 + x];
			block[y * 8 + x] = block[x * 8 + y];
			block[x * 8 + y] = buffer;
		}
}

/**
 * Swap bits along a diagonal in an 8-byte array.
 * \param  row  8-byte array
 */
void swap_bits(unsigned char* row)
{
	unsigned char ret[] = {0, 0, 0, 0, 0, 0, 0, 0};
	for(size_t byte = 0; byte < 8; byte++)
		for(size_t bit = 0; bit < 8; bit++)
			if(row[byte] & (1 << bit))
				ret[bit] |= 1 << byte;
	memcpy(row, ret, 8);
}

/**
 * Create null-terminated string from XML string.
 * \param  dst  a pointer to a pointer to bytestring that will of \plen + 1 that
 *              will contain \pxml
 * \param  len  a pointer to size_t that will store the length of \plen
 * \param  xml  string extracted from the XML tree
 */
void ccf_xml_query(char** dst, size_t* len, xmlChar* untouched)
{
	*len = xmlStrlen(untouched);
	*dst = malloc(*len + 1);
	strcpy(*dst, (char*)untouched);
	xmlFree(untouched);
}

/**
 * Parse and save <Download> tag.
 * \param  link      link_list element the data is written to
 * \param  download  XML node
 */
void ccf_xml_parse_download(struct link_list* link, xmlNode* download)
{
	static const unsigned char URL      = 0x1;
	static const unsigned char FILENAME = 0x2;
	static const unsigned char SIZE     = 0x4;
	unsigned char done = 0;
	link->url          = NULL;
	link->url_len      = 0;
	link->filename     = NULL;
	link->filename_len = 0;
	link->filesize     = -1;
	for(xmlNode* attribute = download->xmlChildrenNode; attribute
			&& done != (URL | FILENAME | SIZE); attribute = attribute->next)
	{
		if(~done & URL && xmlStrcmp(attribute->name, (const xmlChar*)"Url") == 0)
		{
			ccf_xml_query(&link->url, &link->url_len, xmlNodeGetContent(attribute));
			done |= URL;
		}
		else if(~done & FILENAME && xmlStrcmp(attribute->name, (const xmlChar*)"FileName") == 0)
		{
			ccf_xml_query(&link->filename, &link->filename_len, xmlNodeGetContent(attribute));
			done |= FILENAME;
		}
		else if(~done & SIZE && xmlStrcmp(attribute->name, (const xmlChar*)"FileSize") == 0)
		{
			char* data;
			size_t data_len;
			ccf_xml_query(&data, &data_len, xmlNodeGetContent(attribute));
			if(data_len > 18)
				data[18] = '\0';
			link->filesize = atoll(data);
			free(data);
			done |= SIZE;
		}
	}
}

/**
 * Parse and save <Package> tag.
 * \param  package  package_list element the data is written to
 * \param  node     XML node
 */
void ccf_xml_parse_package(struct package_list* package, xmlNode* node)
{
	package->passwords     = NULL;
	package->passwords_len = 0;
	ccf_xml_query(&package->name, &package->name_len, xmlGetProp(node, (const xmlChar*)"name"));
	package->links = NULL;
	struct link_list* last = NULL;
	for(xmlNode* link = node->xmlChildrenNode; link; link = link->next)
		if(xmlStrcmp(link->name, (const xmlChar*)"Download") == 0)
		{
			if(package->links)
			{
				last->next = malloc(sizeof(*last));
				last = last->next;
			}
			else
			{
				package->links = malloc(sizeof(*last));
				last = package->links;
			}
			ccf_xml_parse_download(last, link);
		}
	if(package->links)
		last->next = NULL;
}

/**
 * Parse decrypted CCF data.
 * \param  data  "decrypted" CCF file content
 * \param  len   length of \pdata
 */
struct package_list* parse_ccf(const char* data, size_t len)
{
	struct package_list* first = NULL;
	struct package_list* last;
	xmlDoc*  doc  = xmlReadMemory((char*)data, len, NULL, NULL, 0);
	xmlNode* root = xmlDocGetRootElement(doc);
	for(xmlNode* package = root->xmlChildrenNode; package; package = package->next)
		if(xmlStrcmp(package->name, (const xmlChar*)"Package") == 0)
		{
			if(first)
			{
				last->next = malloc(sizeof(*last));
				last = last->next;
			}
			else
			{
				first = malloc(sizeof(*last));
				last = first;
			}
			ccf_xml_parse_package(last, package);
		}
	if(first)
		last->next = NULL;
	xmlFreeDoc(doc);
	return first;
}

#define CCF30_BLOCK_SIZE 64

/**
 * Decrypt CCF 3.0 data.
 * \param  data  CCF file content
 * \param  len   length of \pdata
 */
struct package_list* decrypt_ccf3(const unsigned char* data, size_t len)
{
	if(len % 64 != 5)
		return NULL;
	uint32_t magic;
	memcpy(&magic, data, 4);
	unsigned char padding = 64 - data[4];
	size_t decoded_len = len - 5;
	char* decoded = malloc(decoded_len);
	if(decoded)
	{
		for(size_t start = 5; start < len; start += CCF30_BLOCK_SIZE)
		{
			unsigned char block[64];
			memcpy(block, data + start, 64);
			// swap rows and columns
			for(size_t i = 0; i < CCF30_BLOCK_SIZE; i++)
			{
				// do the magic
				if(magic & 1)
					magic = rotate_right(magic, (magic & 0xff) % 12);
				else
					magic = rotate_left(magic, (magic & 0xff) % 9);
				block[i] ^= magic & 0xff;
				swap_bytes_by_main_diagonal(block, 8, 8);
			}
			// bitwise swap
			for(size_t y = 0; y < 8; y++)
			{
				unsigned char* row = block + y * 8;
				for(size_t x = 0; x < 8; x++)
				{
					row[x] ^= magic & 0xff;
					swap_bits(row);
					// do the magic
					if(magic & 1)
						magic = rotate_right(magic, magic & 12);
					else
						magic = rotate_left(magic, magic & 9);
				}
			}
			memcpy(decoded + start - 5, block, CCF30_BLOCK_SIZE);
		}
		size_t offset = 0;
		for(; strncmp(decoded + offset, "?>", 2) != 0; offset++);
		offset += 2;
		struct package_list* packages = parse_ccf(decoded + offset,
				decoded_len - padding - offset);
		free(decoded);
		return packages;
	}
	else
		return NULL;
}

/**
 * Decrypt CCF 5.0 data.
 * \param  data  CCF file content
 * \param  len   length of \pdata
 */
struct package_list* decrypt_ccf5(const unsigned char* data, size_t len)
{
	char* decrypted = malloc(len);
	if(decrypted)
	{
		static const unsigned char key[] = {
				0x5f, 0x67, 0x9c, 0x00, 0x54, 0x87, 0x37, 0xe1, 0x20, 0xe6, 0x51,
				0x8a, 0x98, 0x1b, 0xD0, 0xba, 0x11, 0xaf, 0x5c, 0x71, 0x9e, 0x97,
				0x50, 0x29, 0x83, 0xad, 0x6a, 0xa3, 0x8e, 0xd7, 0x21, 0xc3};
		static const unsigned char iv[] = {
				0xe3, 0xd1, 0x53, 0xad, 0x60, 0x9e, 0xf7, 0x35, 0x8d, 0x66, 0x68,
				0x41, 0x80, 0xc7, 0x33, 0x1a};
		openssl_evp_decrypt((unsigned char*)decrypted, data, len, EVP_aes_256_cbc(),
				key, iv, 0);
		struct package_list* packages = parse_ccf(decrypted, len);
		free(decrypted);
		return packages;
	}
	else
		return NULL;
}

struct package_list* decrypt_ccf(const unsigned char* data, size_t len)
{
	if(strncmp((char*)data, "CCF3.0", 6) == 0)
		return decrypt_ccf3(data + 6, len - 6);
	else
		return decrypt_ccf5(data, len);
}
