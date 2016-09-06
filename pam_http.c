#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <security/pam_modules.h>
#include <syslog.h>
#include <curl/curl.h>

/* expected hook */
PAM_EXTERN int pam_sm_setcred( pam_handle_t *pamh, int flags, int argc, const char **argv ) {
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t *pamh, int flags, int argc, const char **argv) {
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

	syslog(LOG_DEBUG, "Authentication %s", res != 22 ? "successful" : "failed");

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

	struct pam_message msg;
	struct pam_conv* pItem;
	struct pam_response* pResp;
	const struct pam_message* pMsg = &msg;

	int timeout = 10;

    openlog("pam_http", LOG_ODELAY, LOG_AUTH);

    if(_get_argument("debug", argc, argv)) {
        setlogmask(LOG_UPTO(LOG_DEBUG));
    } else {
        setlogmask(LOG_UPTO(LOG_WARNING));
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
		timeout = atoi(pTimeout);
		if (timeout < 1) timeout = 1;
	}

	pKey = _get_argument("key", argc, argv);

	if (!pKey)
		pKey = getenv("PAM_HTTP_KEY");

	pItem->conv(1, &pMsg, &pResp, pItem->appdata_ptr);

	if (pam_get_item(pamh, PAM_RHOST, (const void**)&pHost) != PAM_SUCCESS) {
		syslog(LOG_ERR, "Unable to obtain remote address.");
		pHost = NULL;
	}

	ret = PAM_SUCCESS;

	if (perform_authentication(pUrl, pUsername, pResp[0].resp, pCaFile, pKey, pHost, timeout) != 0) {
		syslog(LOG_ERR, "Authentication failed.");
		ret = PAM_AUTH_ERR;
	}

	memset(pResp[0].resp, 0, strlen(pResp[0].resp));
	free(pResp);

	return ret;
}
