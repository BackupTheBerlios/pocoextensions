//
// HTTPCredentials.cpp
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#include "Poco/Net/HTTPAuthenticationParams.h"
#include "Poco/Net/HTTPBasicCredentials.h"
#include "Poco/Net/HTTPCredentials.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/NetException.h"
#include "Poco/String.h"
#include "Poco/URI.h"


using Poco::icompare;


namespace Poco {
namespace Net {


HTTPCredentials::HTTPCredentials():
    _digest()
{
}


HTTPCredentials::HTTPCredentials(const std::string& username, const std::string& password):
    _digest(username, password)
{
}


HTTPCredentials::~HTTPCredentials()
{
}


void
HTTPCredentials::authenticate(HTTPRequest& request, const HTTPResponse& response)
{
    for (HTTPResponse::ConstIterator iter = response.find("WWW-Authenticate");
         iter != response.end();
         ++iter)
    {
        if (isBasicCredentials(iter->second)) {
            HTTPBasicCredentials(_digest.getUsername(), _digest.getPassword()).authenticate(request);
            return;
        } else if (isDigestCredentials(iter->second)) {
            _digest.authenticate(request, HTTPAuthenticationParams(iter->second.substr(7)));
            return;
        }
    }
}


void HTTPCredentials::updateAuthInfo(HTTPRequest& request)
{
    if (request.has("Authorization")) {
        const std::string& authorization = request.get("Authorization");

        if (isBasicCredentials(authorization)) {
            HTTPBasicCredentials(_digest.getUsername(), _digest.getPassword()).authenticate(request);
        } else if (isDigestCredentials(authorization)) {
            _digest.updateAuthInfo(request);
        }
    }
}


bool HTTPCredentials::isBasicCredentials(const std::string& header)
{
    return icompare(header, 0, 6, "Basic ") == 0;
}


bool HTTPCredentials::isDigestCredentials(const std::string& header)
{
    return icompare(header, 0, 7, "Digest ") == 0;
}


void HTTPCredentials::extractCredentials(const std::string& userInfo, std::string& username, std::string& password)
{
    const size_t p = userInfo.find(':');

    if (p != std::string::npos) {
        username.assign(userInfo, 0, p);
        password.assign(userInfo, p + 1, std::string::npos);
    } else {
        username.assign(userInfo);
        password.clear();
    }
}


void HTTPCredentials::extractCredentials(const Poco::URI& uri, std::string& username, std::string& password)
{
    if (!uri.getUserInfo().empty()) {
        extractCredentials(uri.getUserInfo(), username, password);
    }
}


} } // namespace Poco::Net
