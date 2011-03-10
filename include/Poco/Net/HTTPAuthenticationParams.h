//
// HTTPAuthenticationParams.h
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


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

    explicit HTTPAuthenticationParams(const std::string& authInfo);
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
    static void formatItem(std::string& result, ConstIterator itemIter);

    static bool mustBeQuoted(const std::string& param);

    void parse(std::string::const_iterator first, std::string::const_iterator last);
};


} } // namespace Poco::Net


#endif // Net_HTTPAuthenticationParams_INCLUDED
