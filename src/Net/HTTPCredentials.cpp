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
#include <cctype>


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
    if (request.has(HTTPRequest::AUTHORIZATION)) {
        const std::string& authorization = request.get(HTTPRequest::AUTHORIZATION);

        if (isBasicCredentials(authorization)) {
            HTTPBasicCredentials(_digest.getUsername(), _digest.getPassword()).authenticate(request);
        } else if (isDigestCredentials(authorization)) {
            _digest.updateAuthInfo(request);
        }
    }
}


void HTTPCredentials::fromUserInfo(const std::string& userInfo)
{
    std::string username;
    std::string password;

    extractCredentials(userInfo, username, password);
    setUsername(username);
    setPassword(password);
    // TODO: Reset digest state?
}


void HTTPCredentials::fromURI(const URI& uri)
{
    std::string username;
    std::string password;

    extractCredentials(uri, username, password);
    setUsername(username);
    setPassword(password);
    // TODO: Reset digest state?
}


bool HTTPCredentials::isBasicCredentials(const std::string& header)
{
    return icompare(header, 0, 5, "Basic") == 0 && (header.size() > 5 ? std::isspace(header[5]) : true);
}


bool HTTPCredentials::isDigestCredentials(const std::string& header)
{
    return icompare(header, 0, 6, "Digest") == 0 && (header.size() > 6 ? std::isspace(header[6]) : true);
}


bool HTTPCredentials::hasBasicCredentials(const HTTPRequest& request)
{
    return request.has(HTTPRequest::AUTHORIZATION) && isBasicCredentials(request.get(HTTPRequest::AUTHORIZATION));
}


bool HTTPCredentials::hasDigestCredentials(const HTTPRequest& request)
{
    return request.has(HTTPRequest::AUTHORIZATION) && isDigestCredentials(request.get(HTTPRequest::AUTHORIZATION));
}


void HTTPCredentials::extractCredentials(const std::string& userInfo, std::string& username, std::string& password)
{
    const size_t p = userInfo.find(':');

    if (p != std::string::npos) {
        if (userInfo.find(':', p + 1) != std::string::npos) {
            throw SyntaxException("Invalid user info", userInfo);
        }
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
