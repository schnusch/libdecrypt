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
#include <stdbool.h>
#include <stdio.h>
#include <curl/curl.h>
#include <openssl/evp.h>
#include <libxml/parser.h>

#include "dlc.h"
#include "bloblist.h"
#include "crypto.h"
#include "encoding.h"
#include "disguise/disguise.h"

/**
 * Extract DLC ID from DLC file content.
 * \param  dlc_id  string -- of at least DLC_ID_LENGTH + 1 characters -- the
 *                 null-terminated DLC ID will be written to
 * \param  data    bytestring containing the DLC file's content
 * \param  len     length of bytestring \pdata
 * \return         number of trailing bytes copied from \pdata
 */
size_t get_dlc_id(char dlc_id[DLC_ID_LENGTH + 1], const char* data, size_t len)
{
	dlc_id[DLC_ID_LENGTH] = '\0';
	size_t dlc_id_copy_len = DLC_ID_LENGTH;
	for(unsigned char i = 1; i <= 2; i++)
		if(data[len - i] != '=')
		{
			dlc_id_copy_len--;
			dlc_id[dlc_id_copy_len] = '=';
		}
	memcpy(dlc_id, data + len - dlc_id_copy_len, dlc_id_copy_len);
	return dlc_id_copy_len;
}

/**
 * Request the encrypted key used for the decryption of the DLC file.
 * \param  dlc_id          null-terminated string containing the DLC ID
 * \param  response_list   struct the response will be written to
 * \param  write_callback  function used to write to \presponse_list
 * \return                 true on success, otherwise false
 */
bool dlc_api_request_client_cipher(char dlc_id[DLC_ID_LENGTH + 1], struct blob_list* response_list, size_t(*write_callback)(void*, size_t, size_t, void*))
{
	CURL* curl = curl_easy_init();
	if(curl)
	{
		void* stuff = dlc_api_curl_custom(curl, dlc_id);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA,     response_list);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		CURLcode res = curl_easy_perform(curl);
		curl_easy_cleanup(curl);
		dlc_api_curl_free(stuff);
		if(res == CURLE_OK)
			return true;
	}
	return false;
}

/**
 * Create null-terminated string from XML string.
 * \param  dst        a pointer to a pointer to bytestring that will of \plen + 1
 *                    that will contain \puntouched decoded from base64
 * \param  len        a pointer to size_t that will store the length of \plen
 * \param  untouched  string extracted from the XML tree
 */
void dlc_xml_unescape_query(char** dst, size_t* len, xmlChar* untouched)
{
	char* encoded;
	size_t encoded_len = base64_find(&encoded, (char*)untouched, xmlStrlen(untouched));
	*len = base64_decode_length(encoded, encoded_len);
	*dst = malloc(*len + 1);
	(*dst)[*len] = '\0';
	base64_decode((unsigned char*)*dst, *len, encoded, encoded_len);
	xmlFree(untouched);
}

/**
 * Parse and save <file> tag.
 * \param  link  link_list element the data is written to
 * \param  file  XML node
 */
void dlc_xml_parse_file(struct link_list* link, xmlNode* file)
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
	for(xmlNode* attribute = file->xmlChildrenNode; attribute
			&& done != (URL | FILENAME | SIZE); attribute = attribute->next)
	{
		if(~done & URL && xmlStrcmp(attribute->name, (const xmlChar*)"url") == 0)
		{
			dlc_xml_unescape_query(&link->url, &link->url_len, xmlNodeGetContent(attribute));
			done |= URL;
		}
		else if(~done & FILENAME && xmlStrcmp(attribute->name, (const xmlChar*)"filename") == 0)
		{
			dlc_xml_unescape_query(&link->filename, &link->filename_len, xmlNodeGetContent(attribute));
			done |= FILENAME;
		}
		else if(~done & SIZE && xmlStrcmp(attribute->name, (const xmlChar*)"size") == 0)
		{
			xmlChar* untouched = xmlNodeGetContent(attribute);
			char* encoded;
			size_t encoded_len = base64_find(&encoded, (char*)untouched, xmlStrlen(untouched));
			size_t decoded_len = base64_decode_length(encoded, encoded_len);
			char* decoded = malloc(decoded_len + 1);
			decoded[decoded_len] = '\0';
			base64_decode((unsigned char*)decoded, decoded_len, encoded, encoded_len);
			xmlFree(untouched);
			if(decoded_len > 18)
				decoded[18] = '\0';
			link->filesize = atoll(decoded);
			free(decoded);
			done |= SIZE;
		}
	}
}

/**
 * Parse and save <package> tag.
 * \param  package  package_list element the data is written to
 * \param  node     XML node
 */
void dlc_xml_parse_package(struct package_list* package, xmlNode* node)
{
	dlc_xml_unescape_query(&package->name, &package->name_len,
			xmlGetProp(node, (const xmlChar*)"name"));
	dlc_xml_unescape_query(&package->passwords, &package->passwords_len,
			xmlGetProp(node, (const xmlChar*)"passwords"));
	package->links = NULL;
	struct link_list* last = NULL;
	for(xmlNode* link = node->xmlChildrenNode; link; link = link->next)
		if(xmlStrcmp(link->name, (const xmlChar*)"file") == 0)
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
			dlc_xml_parse_file(last, link);
		}
	if(package->links)
		last->next = NULL;
}

/**
 * Decrypt and parse DLC data.
 * \param  key_iv  key used to decrypt \pdata
 * \param  data    basically all but the last 88 bytes from the DLC file
 * \param  len     length of \pdata
 */
struct package_list* parse_dlc(const unsigned char key_iv[EVP_aes_128_key_length],
		const char* data, size_t len)
{
	// decode DLC data
	char* untouched;
	size_t untouched_len = base64_find(&untouched, data, len);
	size_t decoded_len = base64_decode_length(untouched, untouched_len);
	unsigned char* workspace = malloc(decoded_len);
	base64_decode(workspace, decoded_len, untouched, untouched_len);
	// decrypt DLC data
	openssl_evp_decrypt(workspace, workspace, decoded_len, EVP_aes_128_cbc(),
			key_iv, key_iv, 0);
	// decode DLC data
	char* encoded;
	size_t encoded_len = base64_find(&encoded, (char*)workspace, decoded_len);
	size_t final_len = base64_decode_length((char*)workspace, encoded_len);
	base64_decode(workspace, final_len, encoded, encoded_len);
	// parse XML
	struct package_list* first = NULL;
	struct package_list* last;
	xmlDoc*  doc  = xmlReadMemory((char*)workspace, final_len, NULL, NULL, 0);
	xmlNode* root = xmlDocGetRootElement(doc);
	xmlNode* content = root->xmlChildrenNode;
	for(; content && xmlStrcmp(content->name, (const xmlChar*)"content") != 0; content = content->next);
	for(xmlNode* package = content->xmlChildrenNode; package; package = package->next)
		if(xmlStrcmp(package->name, (const xmlChar*)"package") == 0)
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
			dlc_xml_parse_package(last, package);
		}
	if(first)
		last->next = NULL;
	xmlFreeDoc(doc);
	free(workspace);
	return first;
}

struct package_list* decrypt_dlc(const char* data, size_t len)
{
	char* dlc_id = malloc(DLC_ID_LENGTH + 1);
	size_t data_len = len - get_dlc_id(dlc_id, data, len);
	struct blob_list* response_list = malloc(sizeof(*response_list));
	response_list->size = 0;
	if(dlc_api_request_client_cipher(dlc_id, response_list, blob_list_write_callback))
	{
		free(dlc_id);
		// assemble response
		size_t response_len = 0;
		for(struct blob_list* element = response_list; element; element = element->next)
			response_len = element->size;
		char* response = malloc(response_len);
		blob_list_to_block(response, response_list);
		// get decryption key
		unsigned char* key_iv = malloc(EVP_aes_128_key_length);
		get_decryption_key(key_iv, EVP_aes_128_key_length, response, response_len);
		free(response);
		// decrypt dlc
		struct package_list* ret = parse_dlc(key_iv, data, data_len);
		free(key_iv);
		return ret;
	}
	else
	{
		free(dlc_id);
		fprintf(stderr, "curl failed.\n");
		return NULL;
	}
}
