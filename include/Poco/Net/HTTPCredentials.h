

#ifndef Net_HTTPCredentials_INCLUDED
#define Net_HTTPCredentials_INCLUDED


#include "Poco/Net/HTTPDigestCredentials.h"


namespace Poco {
namespace Net {


class HTTPRequest;
class HTTPResponse;


class HTTPCredentials
{
public:
    HTTPCredentials();

    explicit
    HTTPCredentials(const std::string& username, const std::string& password);

	void setUsername(const std::string& username);
		/// Sets the username.

	const std::string& getUsername() const;
		/// Returns the username.

	void setPassword(const std::string& password);
		/// Sets the password.

	const std::string& getPassword() const;
		/// Returns the password.

    void authenticate(HTTPRequest& request, const HTTPResponse& response);

protected:
    // HTTPBasicCredentials _basic;
    HTTPDigestCredentials _digest;
};


//
// inlines
//
inline void HTTPCredentials::setUsername(const std::string& username)
{
	_digest.setUsername(username);
}


inline const std::string& HTTPCredentials::getUsername() const
{
	return _digest.getUsername();
}

	
inline void HTTPCredentials::setPassword(const std::string& password)
{
    _digest.setPassword(password);
}


inline const std::string& HTTPCredentials::getPassword() const
{
	return _digest.getPassword();
}


} } // namespace Poco::Net


#endif // Net_HTTPCredentials_INCLUDED
