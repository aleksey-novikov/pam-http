#define _XOPEN_SOURCE    
#define _GNU_SOURCE

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <time.h>
#include <curl/curl.h>

#define DEFAULT_SALT "$6$2e1d104a249e35a966fa44b587108a172b7a90d5ce2b276971a2181187225cb8"

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
	return PAM_SUCCESS;
}

PAM_EXTERN  int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

PAM_EXTERN  int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

/*
 * Makes getting arguments easier.
 *
 * @param pName- name of the argument to get
 * @param argc- number of total arguments
 * @param argv- arguments
 * @return Pointer to value or NULL
 */
static const char* _get_argument(const char* pName, int argc, const char** argv) {
	int len = strlen(pName);
	int i;

	for (i = 0; i < argc; i++) {
		if (strncmp(pName, argv[i], len) == 0) {
            if (argv[i][len] == '=') {
			    // only give the part url part (after the equals sign)
			    return argv[i] + len + 1;
            } else {
                return "";
            }
		}
	}
	return 0;
}

/*
 * Function to handle stuff from HTTP response.
 *
 * @param buf- Raw buffer from libcurl.
 * @param len- number of indices
 * @param size- size of each index
 * @param userdata- any extra user data needed
 * @return Number of bytes actually handled. If different from len * size, curl will throw an error
 */
static int writeFn(void* buf, size_t len, size_t size, void* userdata) {
	return len * size;
}

int lookup_cache(const char* pCacheDir, const char* pUsername, const char* pPassword, const char* pSalt, int timeout) {

    struct stat attrib;
    time_t now_time;
    int len_dir, len_file, len_payload, i;
    char* path;
    char* password_hash;
    char* username_hash;

    password_hash = strdup(crypt(pPassword, pSalt));
    username_hash = strdup(crypt(pUsername, pSalt));

    len_dir = strlen(pCacheDir);
    len_file = strlen(username_hash);
    len_payload = strlen(password_hash);

    path = (char *) malloc(sizeof(char) * (len_dir + len_file + 1));

    if (pCacheDir[len_dir-1] == '/') 
        sprintf(path, "%s%s", pCacheDir, username_hash);
    else
        sprintf(path, "%s/%s", pCacheDir, username_hash);

    time (&now_time);
    if (stat(path, &attrib) == 0) {

        double age = difftime(now_time, attrib.st_ctime);
        if (age < timeout) {

            FILE* fd = fopen(path, "r");

            if (fd) {
                int match = 1;

                for (i = 0; i < len_payload; i++) {
                    int c = getc(fd);

                    if (c == EOF || password_hash[i] != (char) c) {
                        match = 0;
                        break;
                    }

                }

                fclose(fd);
                free(password_hash);
                free(username_hash);
                free(path);

                syslog(LOG_DEBUG, "Cached password for user %s %s.", pUsername, match ? "matches" : "does not match");

                return match ? 0 : -1;
            }
        } else {
            syslog(LOG_DEBUG, "Cache for user %s exists but is stale (%.0f seconds).", pUsername, age);
        }
    } else {
            syslog(LOG_DEBUG, "Cache for user %s does not exist.", pUsername);
    }

    free(password_hash);
    free(username_hash);
    free(path);
    return -1;
}

int store_cache(const char* pCacheDir, const char* pUsername, const char* pPassword, const char* pSalt) {

    int len_dir, len_file;
    char* path;
    FILE* fd;
    char* password_hash;
    char* username_hash;

    password_hash = strdup(crypt(pPassword, pSalt));
    username_hash = strdup(crypt(pUsername, pSalt));

    len_dir = strlen(pCacheDir);
    len_file = strlen(username_hash);

    path = (char *) malloc(sizeof(char) * (len_dir + len_file + 1));

    if (pCacheDir[len_dir-1] == '/') 
        sprintf(path, "%s%s", pCacheDir, username_hash);
    else
        sprintf(path, "%s/%s", pCacheDir, username_hash);

    fd = fopen(path, "w");
    if (!fd) {
        syslog(LOG_DEBUG, "Unable to write cache entry, directory does not exist?");
        return -1;
    }

    fputs(password_hash, fd);
    fclose(fd);

    syslog(LOG_DEBUG, "Writing cache entry for user %s.", pUsername);

    free(password_hash);
    free(username_hash);
    free(path);

    return 0;
}

static int perform_authentication(const char* pUrl, const char* pUsername, const char* pPassword, const char* pCaFile, const char* pKey, const char* pHost, const int timeout) {

	CURL* pCurl = curl_easy_init();
	int res = -1;
	long http_code = 0;
	struct curl_slist *headers = NULL;
	char* pUserPass;
	int len = strlen(pUsername) + strlen(pPassword) + 2; // : separator & trailing null

	if (!pCurl) {
		return 0;
	}

	syslog(LOG_DEBUG, "Authenticating user %s with %s ...", pUsername, pUrl);

	pUserPass = malloc(len);

	sprintf(pUserPass, "%s:%s", pUsername, pPassword);

	curl_easy_setopt(pCurl, CURLOPT_URL, pUrl);
	curl_easy_setopt(pCurl, CURLOPT_WRITEFUNCTION, writeFn);
	curl_easy_setopt(pCurl, CURLOPT_USERPWD, pUserPass);
	curl_easy_setopt(pCurl, CURLOPT_NOPROGRESS, 1); // we don't care about progress
	curl_easy_setopt(pCurl, CURLOPT_FAILONERROR, 1);
//	curl_easy_setopt(pCurl, CURLOPT_HEADERFUNCTION, _read_headers);
//	curl_easy_setopt(pCurl,	CURLOPT_WRITEHEADER, stderr);
	// we don't want to leave our user waiting at the login prompt forever
	curl_easy_setopt(pCurl, CURLOPT_TIMEOUT, timeout);


	if (pKey) {
		int len = 11 + strlen(pKey) + 2;
		char* pHeader = malloc(len);

		syslog(LOG_DEBUG, "Authenticating with key %s", pKey);

		sprintf(pHeader, "X-Api-Key: %s\r\n", pKey);
		headers = curl_slist_append(headers, pHeader);
		curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);

		memset(pHeader, '\0', len);
		free(pHeader);
	}

	if (pHost) {
		int len = 11 + strlen(pKey) + 2;
		char* pHeader = malloc(len);

		sprintf(pHeader, "X-Real-IP: %s\r\n", pKey);
		headers = curl_slist_append(headers, pHeader);
		curl_easy_setopt(pCurl, CURLOPT_HTTPHEADER, headers);

		memset(pHeader, '\0', len);
		free(pHeader);
	}

	// SSL needs 16k of random stuff. We'll give it some space in RAM.
	if (strlen(pUrl) > 5 && strncmp(pUrl, "https", 5) == 0) {

		curl_easy_setopt(pCurl, CURLOPT_RANDOM_FILE, "/dev/urandom");
		curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYPEER, 0);
		curl_easy_setopt(pCurl, CURLOPT_USE_SSL, CURLUSESSL_ALL);

		if (pCaFile) {
			curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 2);
			curl_easy_setopt(pCurl, CURLOPT_CAINFO, pCaFile);
		} else {
			curl_easy_setopt(pCurl, CURLOPT_SSL_VERIFYHOST, 0);
		}

	}

	// synchronous, but we don't really care
	res = curl_easy_perform(pCurl);

	memset(pUserPass, '\0', len);
	free(pUserPass);

	if (headers) {
		curl_slist_free_all(headers);
	}

	if (res) {
		curl_easy_getinfo (pCurl, CURLINFO_RESPONSE_CODE, &http_code);
		if (http_code != 200)
			res = 22;
	}

	curl_easy_cleanup(pCurl);

	syslog(LOG_DEBUG, "Authentication %s.", res != 22 ? "successful" : "failed");

	return res;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t* pamh, int flags, int argc, const char **argv) {
	int ret = 0;

	const char* pUsername = NULL;
	const char* pUrl = NULL;
	const char* pCaFile = NULL;
	const char* pKey = NULL;
	const char* pTimeout = NULL;
	const char* pHost = NULL;
	const char* pSalt = NULL;
	const char* pCacheDir = NULL;
	const char* pCacheTimeout = NULL;

	struct pam_message msg;
	struct pam_conv* pItem;
	struct pam_response* pResp;
	const struct pam_message* pMsg = &msg;

	int connection_timeout = 10;
	int cache_timeout = 60 * 10; // 10 minutes

    openlog("pam_http", LOG_ODELAY, LOG_AUTH);


    if (flags & PAM_SILENT) {
        setlogmask(LOG_UPTO(LOG_EMERG));
    } else {
        if(_get_argument("debug", argc, argv)) {
            setlogmask(LOG_UPTO(LOG_DEBUG));
        } else {
            setlogmask(LOG_UPTO(LOG_WARNING));
        } 
    }
	syslog(LOG_DEBUG, "Entering pam_sm_authenticate.");

	msg.msg_style = PAM_PROMPT_ECHO_OFF;
	msg.msg = "Password: ";

	if (pam_get_user(pamh, &pUsername, NULL) != PAM_SUCCESS) {
		return PAM_AUTH_ERR;
	}

	pUrl = _get_argument("url", argc, argv);

	if (!pUrl)
		pUrl = getenv("PAM_HTTP_URL");

	if (!pUrl) {
        syslog(LOG_ERR, "Authentication URL not provided via url parameter or PAM_HTTP_URL.");
		return PAM_AUTH_ERR;
	}

	pCaFile = _get_argument("cafile", argc, argv);

	if (!pCaFile)
		pCaFile = getenv("PAM_HTTP_CA");

	if (pam_get_item(pamh, PAM_CONV, (const void**)&pItem) != PAM_SUCCESS || !pItem) {
		syslog(LOG_ERR, "Couldn't obtain PAM_CONV.");
		return PAM_AUTH_ERR;
	}

	pTimeout = _get_argument("timeout", argc, argv);

	if (!pTimeout)
		pTimeout = getenv("PAM_HTTP_TIMEOUT");

	if (pTimeout) {
		connection_timeout = atoi(pTimeout);
		if (connection_timeout < 1) connection_timeout = 1;
	}

	pKey = _get_argument("key", argc, argv);

	if (!pKey)
		pKey = getenv("PAM_HTTP_KEY");


	pCacheDir = _get_argument("cache_dir", argc, argv);

	if (!pCacheDir)
		pCacheDir = getenv("PAM_HTTP_CACHE_DIR");

	if (!pCacheDir) {
        syslog(LOG_WARNING, "Cache dir not provided via cache_dir parameter or PAM_HTTP_CACHE_DIR.");
	}

    pSalt = _get_argument("cache_salt", argc, argv);

	if (!pSalt)
		pSalt = getenv("PAM_HTTP_SECRET");

	if (!pSalt) {
        syslog(LOG_WARNING, "Cache salt not provided via cache_salt parameter or PAM_HTTP_CACHE_SECRET, using default.");
		pSalt = DEFAULT_SALT;
	}

	pTimeout = _get_argument("cache_timeout", argc, argv);

	if (!pCacheTimeout)
		pCacheTimeout = getenv("PAM_HTTP_TIMEOUT");

	if (pCacheTimeout) {
		cache_timeout = atoi(pCacheTimeout);
		if (cache_timeout < 1) cache_timeout = 1;
	}


	pItem->conv(1, &pMsg, &pResp, pItem->appdata_ptr);

	if (pam_get_item(pamh, PAM_RHOST, (const void**)&pHost) != PAM_SUCCESS) {
		syslog(LOG_ERR, "Unable to obtain remote address.");
		pHost = NULL;
	}

	ret = PAM_SUCCESS;

    if (pCacheDir && lookup_cache(pCacheDir, pUsername, pResp[0].resp, pSalt, cache_timeout) == 0) {
        return ret;
    }

	if (perform_authentication(pUrl, pUsername, pResp[0].resp, pCaFile, pKey, pHost, connection_timeout) != 0) {
		ret = PAM_AUTH_ERR;
	} else {
        if (pCacheDir)
            store_cache(pCacheDir, pUsername, pResp[0].resp, pSalt);
    }

	memset(pResp[0].resp, 0, strlen(pResp[0].resp));
	free(pResp);

	return ret;
}
