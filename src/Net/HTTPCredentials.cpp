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


#include "Utility.h"


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
        if (isDigestCredentials(request.get("Authorization"))) {
            _digest.updateAuthInfo(request);
        }
    }
}


} } // namespace Poco::Net
