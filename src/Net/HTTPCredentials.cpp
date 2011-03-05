

#include "Poco/Net/HTTPAuthenticationParams.h"
#include "Poco/Net/HTTPBasicCredentials.h"
#include "Poco/Net/HTTPCredentials.h"
#include "Poco/Net/HTTPRequest.h"
#include "Poco/Net/HTTPResponse.h"
#include "Poco/Net/NetException.h"
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
    for (HTTPResponse::ConstIterator iter = response.find("WWW-Authenticate");
         iter != response.end();
         ++iter)
    {
        if (icompare(iter->second, 6, "Basic ") == 0) {
            HTTPBasicCredentials(_digest.getUsername(), _digest.getPassword()).authenticate(request);
            return;
        } else if (icompare(iter->second, 7, "Digest ") == 0) {
            _digest.authenticate(request, HTTPAuthenticationParams(iter->second.substr(7)));
            return;
        }
    }
}


} } // namespace Poco::Net
