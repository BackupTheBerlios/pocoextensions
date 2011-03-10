//
// Utility.h
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#ifndef Net_Utility_INCLUDED
#define Net_Utility_INCLUDED


#include <string>


namespace Poco {


class URI;


namespace Net {


class HTTPResponse;


bool
isBasicCredentials(const std::string& header);


bool
isDigestCredentials(const std::string& header);


void
extractCredentials(const std::string& userInfo, std::string& username, std::string& password);


void
extractCredentials(const Poco::URI& uri, std::string& username, std::string& password);


} } // namespace Poco::Net


#endif // Net_Utility_INCLUDED
