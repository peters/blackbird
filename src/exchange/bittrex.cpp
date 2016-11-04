#include <string.h>
#include <unistd.h>
#include <sstream>
#include <iomanip>  
#include <cctype>
#include <algorithm>
#include <math.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "utils/base64.h"
#include <jansson.h>
#include "bittrex.h"
#include "curl_fun.h"

namespace Bittrex {

double getQuote(Parameters& params, bool isBid) {
  bool GETRequest = true;
  json_t* root = getJsonFromUrl(params, "https://bittrex.com/api/v1.1/public/getticker?market=USDT-BTC", "", GETRequest);
  json_t* result = json_object_get(root, "result");
  double quoteValue;
  if (isBid) {
	quoteValue = json_number_value(json_object_get(result, "Bid"));
  } else {
	quoteValue = json_number_value(json_object_get(result, "Ask"));
  }
  if (quoteValue == NULL) {
	  quoteValue = 0.0;
  }
  json_decref(result);
  json_decref(root);
  return quoteValue;
}

double getAvail(Parameters& params, std::string currency) {
  json_t* root = authRequest(params, "https://bittrex.com/api/v1.1/", "account/getbalances", "");
  if (!root) {
	  goto done;
  }

  json_t* result = json_object_get(root, "result");
  if (!json_is_array(result)) {
	  goto done;
  }

  double balance = 0.0;
  const int arraySize = json_array_size(result);
  for (int i = 0; i < arraySize; i++) {
	  std::string cmpCurrency = json_string_value(json_object_get(json_array_get(result, i), "Currency"));
	  std::transform(cmpCurrency.begin(), cmpCurrency.end(), cmpCurrency.begin(), std::tolower);
	  if (currency.compare(cmpCurrency) == 0) {
		  balance = json_number_value(json_object_get(json_array_get(result, i), "Balance"));
		  goto done;
	  }
  }

  done:
  if (result) {
	  json_decref(result);
  }
  if (root) {
	  json_decref(root);
  }
  return balance;
}

int sendLongOrder(Parameters& params, std::string direction, double quantity, double price) {
  return -1;
}

int sendShortOrder(Parameters& params, std::string direction, double quantity, double price) {
  return -1;
}

int sendOrder(Parameters& params, std::string direction, double quantity, double price) {
  return -1;
}

bool isOrderComplete(Parameters& params, int orderId) {
  if (orderId == 0) {
    return true;
  }
  return false;
}

double getActivePos(Parameters& params) {
	return 0;
}

double getLimitPrice(Parameters& params, double volume, bool isBid) {
  return 0;
}

json_t* authRequest(Parameters& params, std::string url, std::string request, std::string options) {
	struct timeval tv;
	gettimeofday(&tv, NULL);
	unsigned long long nonce = (tv.tv_sec * 1000.0) + (tv.tv_usec * 0.001) + 0.5;

	std::ostringstream buffer;
	buffer << request << "?apikey=" << params.bittrexApi << "&nonce=" << nonce << options;
	url.append(buffer.str());
	
	unsigned char hash[SHA512_DIGEST_LENGTH];

	HMAC_CTX hmac;
	HMAC_CTX_init(&hmac);
	HMAC_Init_ex(&hmac, &params.bittrexSecret[0], params.bittrexSecret.length(), EVP_sha512(), NULL);
	HMAC_Update(&hmac, (unsigned char*)&url[0], url.length());
	unsigned int len = SHA512_DIGEST_LENGTH;
	HMAC_Final(&hmac, hash, &len);
	HMAC_CTX_cleanup(&hmac);

	std::stringstream signature;
	signature << std::hex << std::setfill('0');
	for (int i = 0; i < len; i++)
	{
		signature << std::hex << std::setw(2) << (unsigned int)hash[i];
	}

	CURLcode resCurl;
	if (params.curl) {
		struct curl_slist *headers = NULL;
		buffer.clear();
		buffer.str("");
		buffer << "apisign:" << signature.str();
		headers = curl_slist_append(headers, buffer.str().c_str());

		std::string readBuffer;
		curl_easy_setopt(params.curl, CURLOPT_HTTPHEADER, headers);
		curl_easy_setopt(params.curl, CURLOPT_SSL_VERIFYPEER, 0L);
		curl_easy_setopt(params.curl, CURLOPT_WRITEFUNCTION, WriteCallback);
		curl_easy_setopt(params.curl, CURLOPT_WRITEDATA, &readBuffer);
		curl_easy_setopt(params.curl, CURLOPT_URL, url.c_str());
		curl_easy_setopt(params.curl, CURLOPT_CONNECTTIMEOUT, 10L);
		resCurl = curl_easy_perform(params.curl);
		json_t* root;
		json_error_t error;
		while (resCurl != CURLE_OK) {
			*params.logFile << "<Bittrex> Error with cURL. Retry in 2 sec..." << std::endl;
			sleep(2.0);
			readBuffer = "";
			resCurl = curl_easy_perform(params.curl);
		}
		root = json_loads(readBuffer.c_str(), 0, &error);
		while (!root) {
			*params.logFile << "<Bittrex> Error with JSON:\n" << error.text << std::endl;
			*params.logFile << "<Bittrex> Buffer:\n" << readBuffer.c_str() << std::endl;
			*params.logFile << "<Bittrex> Retrying..." << std::endl;
			sleep(2.0);
			readBuffer = "";
			resCurl = curl_easy_perform(params.curl);
			while (resCurl != CURLE_OK) {
				*params.logFile << "<Bittrex> Error with cURL. Retry in 2 sec..." << std::endl;
				sleep(2.0);
				readBuffer = "";
				resCurl = curl_easy_perform(params.curl);
			}
			root = json_loads(readBuffer.c_str(), 0, &error);
		}
		curl_easy_reset(params.curl);
		curl_slist_free_all(headers);
		return root;
	}
	else {
		*params.logFile << "<Bittrex> Error with cURL init." << std::endl;
		return NULL;
	}
}

}

