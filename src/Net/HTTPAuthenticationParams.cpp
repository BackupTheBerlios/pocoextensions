

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

    if (icompare(header, 6, "Basic ") == 0) {
        parse(header.begin() + 6, header.end());
    } else if (icompare(header, 7, "Digest ") == 0) {
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
    ConstIterator it = begin();
    std::string result;

    if (it != end()) {
        result += it->first;
        result += '=';
        result += it->second;   // TODO: Quoted.
        ++it;
    }

    for (; it != end(); ++it) {
        result += ',';
        result += it->first;
        result += '=';
        result += it->second;   // TODO: Quoted.
    }

    return result;
}


// void HTTPAuthenticationParams::splitQop(std::vector<std::string>& options) const
// {
//     options.clear();
//     if (has("qop")) {
//         const StringTokenizer tokens(get("qop"),
//                                      ",",
//                                      StringTokenizer::TOK_IGNORE_EMPTY |
//                                      StringTokenizer::TOK_TRIM);
// 
//         options.assign(tokens.begin(), tokens.end());
//     }
// }


void HTTPAuthenticationParams::parse(std::string::const_iterator begin,
                                     std::string::const_iterator end)
{
    // enum State {
    //     INITIAL,
    //     PARAMETER_NAME,
    //     ASSIGNMENT,
    //     QUOTED_PARAMETER_VALUE,
    //     PARAMETER_VALUE,
    //     SEPARATOR
    // };
    // 
    // int         s = INITIAL;
    // std::string k;
    // std::string v;
    // 
    // for (std::string::const_iterator it = begin; it != end; ++it) {
    //     switch (state) {
    //     case INITIAL :
    //         if (std::isalnum(*it)) {
    //             state = PARAMETER_NAME;
    //             k += *it;
    //         } else if (std::isspace(*it)) {
    //             // skip
    //         } else {
    //             throw SyntaxException("Invalid authentication information", authInfo);
    //         }
    //         break;
    // 
    //     case PARAMETER_NAME :
    //         if (*it == '=') {
    //             state = ASSIGNMENT;
    //         } else if (std::isalnum(*it)) {
    //             k += *it;
    //         } else {
    //             throw SyntaxException("Invalid authentication information", authInfo);
    //         }
    //         break;
    // 
    //     case ASSIGNMENT :
    //         if (*it == '"') {
    //             state = QUOTED_PARAMETER_VALUE;
    //         } else if (std::isalnum(*it)) {
    //             state = PARAMETER_VALUE;
    //             v += *it;
    //         } else {
    //             throw SyntaxException("Invalid authentication information", authInfo);
    //         }
    //         break;
    // 
    //     case QUOTED_PARAMETER_VALUE :
    //         if (*it == '"') {
    //             state = SEPARATOR;
    //             add(k, v);
    //             k.clear();
    //             v.clear();
    //         } else {
    //             v += *it;
    //         }
    //         break;
    // 
    //     case PARAMETER_VALUE :
    //         if (*it == ',') {
    //             state = INITIAL;
    //             add(k, v);
    //             k.clear();
    //             v.clear();
    //         } else if (std::isspace(*it)) {
    //             state = SEPARATOR;
    //             add(k, v);
    //             k.clear();
    //             v.clear();
    //         } else {
    //             v += *it;
    //         }
    //         break;
    // 
    //     case SEPARATOR :
    //         if (*it == ',') {
    //             state = INITIAL;
    //         } else if (std::isspace(*it)) {
    //             // skip
    //         }
    //         break;
    //     }
    // }
    // 
    // if (state != SEPARATOR && state != PARAMETER_VALUE) {
    //     throw SyntaxException("Invalid authentication information", authInfo);
    // }

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

    int         state = STATE_TOKEN;
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


} } // namespace Poco::Net
