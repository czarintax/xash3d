/*
sv_security.c - Ip checks
Copyright (C) 2023 bariscodefx
*/

#include "common.h"
#include "server.h"
#include <curl/curl.h>

#define MAX_SAFE_IPS 64
char safe_ips[MAX_SAFE_IPS][16];
int cIps = 0;

struct MemoryStruct {
	char *memory;
	size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	char *ptr = realloc(mem->memory, mem->size + realsize + 1);
	if (ptr == NULL) {
		/* out of memory! */
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->memory = ptr;
	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}

char* get_data_from_url(char* url) {
	CURL *curl;
	CURLcode res;
	struct MemoryStruct chunk;
	chunk.memory = malloc(1);  /* will be grown as needed by the realloc above */
	chunk.size = 0;    /* no data at this point */

	curl = curl_easy_init();
	if (curl) {
		curl_easy_setopt(curl, CURLOPT_URL, url);
		curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    
    struct curl_slist *header = NULL;
    curl_slist *header = curl_slist_append(NULL, "X-API-Key: WuCS7KQtyoRxbWDZ4zsSbjUdU4T");

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
    
		res = curl_easy_perform(curl);

		if (res != CURLE_OK) {
			fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
		}

		curl_easy_cleanup(curl);
	}

	return chunk.memory;
}

char *SV_QueryIP(netadr_t from)
{
	char *url = "";
	char *response = "";

	if (from.type == NA_LOOPBACK || !Q_strcmp(NET_BaseAdrToString(from), "135.181.76.187")) // ms.xash.su and localhost
		return response;

	Q_snprintf(url, 330, "http://ip-api.com/json/%s?fields=status,message,country,countryCode,isp,org,as,mobile,proxy,hosting,query", NET_BaseAdrToString(from));

	response = get_data_from_url(url);

	return response;
}

qboolean SV_CheckIPProxy(char *response, netadr_t from)
{
	if (Q_strstr(response, "\"proxy\":true"))
		return true;

	return false;
}

qboolean SV_CheckIPHosting(char *response, netadr_t from)
{
	if (Q_strstr(response, "\"hosting\":true"))
		return true;

	char hostings[3][32] = {
		"limited",
		"free",
		"worldstream"
	};

	for (int i = 0; i < sizeof(hostings); i++)
	{
		if (hostings[i][0] == '\0') break;

		if (Q_strstr(response, hostings[i]))
		{
			return true;
		}
	}

	return false;
}

qboolean SV_CheckIPMobile(char *response, netadr_t from)
{
	if (Q_strstr(response, "\"mobile\":true"))
		return true;

	return false;
}

qboolean SV_CheckSafeIP(netadr_t from)
{
	for (int i = 0; i < cIps; i++)
	{
		if (!strcmp(NET_BaseAdrToString(from), safe_ips[i]))
		{
			return true;
		}
	}

	return false;
}

void SV_AddSafeIP(netadr_t from)
{
	if (cIps > MAX_SAFE_IPS)
	{
		for (int i = 0; i < cIps; i++)
		{
			memset(safe_ips[i], 0, sizeof(safe_ips[i]));
		}
		cIps = 0;
	}

	Q_strncpy(safe_ips[cIps], NET_BaseAdrToString(from), 16);
	cIps++;
}
