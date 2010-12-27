

#ifndef Net_Utility_INCLUDED
#define Net_Utility_INCLUDED


#include <string>


namespace Poco {
namespace Net {


class HTTPResponse;


bool
hasAuthenticateHeader(const HTTPResponse& response);


void
getAuthenticateHeader(const HTTPResponse& response, std::string& scheme, std::string& authInfo);


} } // namespace Poco::Net


#endif // Net_Utility_INCLUDED
