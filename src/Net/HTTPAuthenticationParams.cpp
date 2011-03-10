//
// HTTPAuthenticationParams.cpp
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#include "Poco/Exception.h"
#include "Poco/Net/HTTPAuthenticationParams.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/NetException.h"
#include "Poco/String.h"
#include <cctype>


using Poco::icompare;


namespace Poco {
namespace Net {


const std::string HTTPAuthenticationParams::REALM = "realm";


HTTPAuthenticationParams::HTTPAuthenticationParams() :
    NameValueCollection()
{
}


HTTPAuthenticationParams::HTTPAuthenticationParams(const std::string& authInfo) :
    NameValueCollection()
{
    fromAuthInfo(authInfo);
}


HTTPAuthenticationParams::HTTPAuthenticationParams(const HTTPRequest& request) :
    NameValueCollection()
{
    fromRequest(request);
}


HTTPAuthenticationParams::HTTPAuthenticationParams(const HTTPResponse& response) :
    NameValueCollection()
{
    fromResponse(response);
}


HTTPAuthenticationParams::~HTTPAuthenticationParams()
{
}


void HTTPAuthenticationParams::fromAuthInfo(const std::string& authInfo)
{
    parse(authInfo.begin(), authInfo.end());
}


void HTTPAuthenticationParams::fromRequest(const HTTPRequest& request)
{
    std::string scheme;
    std::string authInfo;

    request.getCredentials(scheme, authInfo);
    if (icompare(scheme, "Digest") != 0) {
        throw InvalidArgumentException("Could not parse non-Digest authentication information", scheme);
    }
    fromAuthInfo(authInfo);
}


void HTTPAuthenticationParams::fromResponse(const HTTPResponse& response)
{
    if (!response.has("WWW-Authenticate")) {
        throw NotAuthenticatedException("HTTP response has no authentication header");
    }

    const std::string& header = response.get("WWW-Authenticate");

    if (icompare(header, 0, 6, "Basic ") == 0) {
        parse(header.begin() + 6, header.end());
    } else if (icompare(header, 0, 7, "Digest ") == 0) {
        parse(header.begin() + 7, header.end());
    } else {
        throw InvalidArgumentException("Invalid authentication scheme", header);
    }
}


const std::string& HTTPAuthenticationParams::getRealm() const
{
    return get(REALM);
}


void HTTPAuthenticationParams::setRealm(const std::string& realm)
{
    set(REALM, realm);
}


std::string HTTPAuthenticationParams::toString() const
{
    ConstIterator iter = begin();
    std::string result;

    if (iter != end()) {
        formatItem(result, iter);
        ++iter;
    }

    for (; iter != end(); ++iter) {
        result.append(", ");
        formatItem(result, iter);
    }

    return result;
}


void HTTPAuthenticationParams::parse(std::string::const_iterator begin, std::string::const_iterator end)
{
    enum State {
        STATE_INITIAL = 0x0100,
        STATE_FINAL = 0x0200,

        STATE_SPACE = STATE_INITIAL | 0,
        STATE_TOKEN = 1,
        STATE_EQUALS = 2,
        STATE_VALUE = STATE_FINAL | 3,
        STATE_VALUE_QUOTED = 4,
        STATE_VALUE_ESCAPE = 5,
        STATE_COMMA = STATE_FINAL | 6
    };

    int         state = STATE_SPACE;
    std::string token;
    std::string value;

    for (std::string::const_iterator it = begin; it != end; ++it) {
        switch (state) {
        case STATE_SPACE :
            if (std::isalnum(*it)) {
                token += *it;
                state = STATE_TOKEN;
            } else if (std::isspace(*it)) {
                // Skip
            } else {
                throw SyntaxException("Invalid authentication information");
            }
            break;

        case STATE_TOKEN :
            if (*it == '=') {
                state = STATE_EQUALS;
            } else if (std::isalnum(*it)) {
                token += *it;
            } else {
                throw SyntaxException("Invalid authentication information");
            }
            break;

        case STATE_EQUALS :
            if (std::isalnum(*it)) {
                value += *it;
                state = STATE_VALUE;
            } else if (*it == '"') {
                state = STATE_VALUE_QUOTED;
            } else {
                throw SyntaxException("Invalid authentication information");
            }
            break;

        case STATE_VALUE_QUOTED :
            if (*it == '\\') {
                state = STATE_VALUE_ESCAPE;
            } else if (*it == '"') {
                add(token, value);
                token.clear();
                value.clear();
                state = STATE_COMMA;
            } else {
                value += *it;
            }
            break;

        case STATE_VALUE_ESCAPE :
            value += *it;
            state = STATE_VALUE_QUOTED;
            break;

        case STATE_VALUE :
            if (std::isspace(*it)) {
                add(token, value);
                token.clear();
                value.clear();
                state = STATE_COMMA;
            } else if (*it == ',') {
                add(token, value);
                token.clear();
                value.clear();
                state = STATE_SPACE;
            } else {
                value += *it;
            }
            break;

        case STATE_COMMA :
            if (*it == ',') {
                state = STATE_SPACE;
            } else if (std::isspace(*it)) {
                // Skip
            } else {
                throw SyntaxException("Invalid authentication information");
            }
            break;
        }
    }

    if (!(state & STATE_FINAL)) {
        throw SyntaxException("Invalid authentication information");
    }
}


void HTTPAuthenticationParams::formatItem(std::string& result, ConstIterator itemIter)
{
    result += itemIter->first;
    result += '=';
    if (mustBeQuoted(itemIter->first)) {
        result += '"';
        result += itemIter->second;
        result += '"';
    } else {
        result += itemIter->second;
    }
}


bool HTTPAuthenticationParams::mustBeQuoted(const std::string& param)
{
    return
        icompare(param, "cnonce") == 0 ||
        icompare(param, "domain") == 0 ||
        icompare(param, "nonce") == 0 ||
        icompare(param, "opaque") == 0 ||
        icompare(param, "qop") == 0 ||
        icompare(param, "realm") == 0 ||
        icompare(param, "response") == 0 ||
        icompare(param, "uri") == 0 ||
        icompare(param, "username") == 0;
}


} } // namespace Poco::Net
