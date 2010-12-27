

#ifndef Net_HTTPDigestCredentials_INCLUDED
#define Net_HTTPDigestCredentials_INCLUDED


#include <map>


#include "Poco/Net/Net.h"


namespace Poco {


class DigestEngine;


namespace Net {


class HTTPRequest;
class HTTPResponse;


class Net_API HTTPDigestCredentials
	/// This is a utility class for working with
	/// HTTP Digest Authentication in HTTPRequest
	/// objects.
{
public:
	HTTPDigestCredentials();
		/// Creates an empty HTTPDigestCredentials object.

	HTTPDigestCredentials(const std::string& username, const std::string& password);
		/// Creates a HTTPDigestCredentials object with the given username and password.

	void setUsername(const std::string& username);
		/// Sets the username.

	const std::string& getUsername() const;
		/// Returns the username.

	void setPassword(const std::string& password);
		/// Sets the password.

	const std::string& getPassword() const;
		/// Returns the password.
		
    void authenticate(HTTPRequest& request, const HTTPResponse& response);
		/// Adds authentication information to the given HTTPRequest.

	static const std::string SCHEME;

private:
	HTTPDigestCredentials(const HTTPDigestCredentials&);
	HTTPDigestCredentials& operator = (const HTTPDigestCredentials);

    std::string _username;
    std::string _password;
    std::string _cnonce;
    std::map<std::string, int> _nc;
};


//
// inlines
//
inline const std::string& HTTPDigestCredentials::getUsername() const
{
	return _username;
}


inline const std::string& HTTPDigestCredentials::getPassword() const
{
	return _password;
}


} } // namespace Poco::Net


#endif // Net_HTTPDigestCredentials_INCLUDED
