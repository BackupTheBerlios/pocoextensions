//
// Utility.cpp
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#include "Poco/Exception.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/Utility.h"
#include "Poco/URI.h"


namespace Poco {
namespace Net {


bool
isBasicCredentials(const std::string& header)
{
    return icompare(header, 0, 6, "Basic ") == 0;
}


bool
isDigestCredentials(const std::string& header)
{
    return icompare(header, 0, 7, "Digest ") == 0;
}


void
extractCredentials(const std::string& userInfo, std::string& username, std::string& password)
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


void
extractCredentials(const Poco::URI& uri, std::string& username, std::string& password)
{
    if (!uri.getUserInfo().empty()) {
        extractCredentials(uri.getUserInfo(), username, password);
    }
}


} } // namespace Poco::Net
