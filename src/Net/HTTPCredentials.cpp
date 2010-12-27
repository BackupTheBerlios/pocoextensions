

#include "Poco/Net/HTTPBasicCredentials.h"
#include "Poco/Net/HTTPCredentials.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/Utility.h"
#include "Poco/String.h"


using Poco::icompare;


namespace Poco {
namespace Net {


HTTPCredentials::HTTPCredentials()
{
}


HTTPCredentials::HTTPCredentials(const std::string& username, const std::string& password):
    _digest(username, password)
{
}


void
HTTPCredentials::authenticate(HTTPRequest& request, const HTTPResponse& response)
{
    if (!hasAuthenticateHeader(response)) {
        return;
    }

    std::string scheme;
    std::string authInfo;

    getAuthenticateHeader(response, scheme, authInfo);

    if (icompare(scheme, "Basic") == 0) {
        HTTPBasicCredentials(_digest.getUsername(), _digest.getPassword()).authenticate(request);
    } else {
        _digest.authenticate(request, response);
    }
}


} } // namespace Poco::Net
