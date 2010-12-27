

#include "Poco/Exception.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/NetException.h"
#include "Poco/Net/Utility.h"


namespace Poco {
namespace Net {


bool
hasAuthenticateHeader(const HTTPResponse& response)
{
    return response.has("WWW-Authenticate");
}


void
getAuthenticateHeader(const HTTPResponse& response, std::string& scheme, std::string& authInfo)
{
    if (!response.has("WWW-Authenticate")) {
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
