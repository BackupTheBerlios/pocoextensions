

#ifndef Net_HTTPAuthenticationParams_INCLUDED
#define Net_HTTPAuthenticationParams_INCLUDED


#include "Poco/Net/NameValueCollection.h"
#include <string>


namespace Poco {
namespace Net {


class HTTPRequest;
class HTTPResponse;


class HTTPAuthenticationParams : public NameValueCollection
	/// TODO
{
public:
    HTTPAuthenticationParams();
		/// TODO

    explicit HTTPAuthenticationParams(const HTTPRequest& request);
		/// TODO

    explicit HTTPAuthenticationParams(const HTTPResponse& response);
		/// TODO

    ~HTTPAuthenticationParams();
		/// TODO

    void fromAuthInfo(const std::string& authInfo);
		/// TODO

    void fromRequest(const HTTPRequest& request);
		/// TODO

    void fromResponse(const HTTPResponse& response);
		/// TODO

    void setRealm(const std::string& realm);
		/// TODO

    const std::string& getRealm() const;
		/// TODO

    std::string toString() const;
        /// TODO

    static const std::string REALM;

private:
    void parse(std::string::const_iterator begin,
               std::string::const_iterator end);
};


} } // namespace Poco::Net


#endif // Net_HTTPAuthenticationParams_INCLUDED
