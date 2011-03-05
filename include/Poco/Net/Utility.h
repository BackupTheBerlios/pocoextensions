

#ifndef Net_Utility_INCLUDED
#define Net_Utility_INCLUDED


#include <string>


namespace Poco {


class URI;


namespace Net {


class HTTPResponse;


void
extractCredentials(const std::string& userInfo, std::string& username, std::string& password);


void
extractCredentials(const Poco::URI& uri, std::string& username, std::string& password);


bool
hasAuthenticateHeader(const HTTPResponse& response);


void
getAuthenticateHeader(const HTTPResponse& response, std::string& scheme, std::string& authInfo);


} } // namespace Poco::Net


#endif // Net_Utility_INCLUDED
