

#include "Poco/Exception.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/Utility.h"
#include "Poco/URI.h"


namespace Poco {
namespace Net {


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


bool
hasAuthenticateHeader(const HTTPResponse& response)
{
    return response.has("WWW-Authenticate");
}


void
getAuthenticateHeader(const HTTPResponse& response, std::string& scheme, std::string& authInfo)
{
    if (!hasAuthenticateHeader(response)) {
        throw NotAuthenticatedException("HTTP response has no authentication header");
    }

    const std::string& header = response.get("WWW-Authenticate");

    if (icompare(header, 6, "Basic ") == 0) {
        scheme.assign(header.begin(), header.begin() + 5);
        authInfo.assign(header.begin() + 6, header.end());
    } else if (icompare(header, 7, "Digest ") == 0) {
        scheme.assign(header.begin(), header.begin() + 6);
        authInfo.assign(header.begin() + 7, header.end());
    } else {
        throw InvalidArgumentException("Invalid authentication scheme", header);
    }
}


} } // namespace Poco::Net
