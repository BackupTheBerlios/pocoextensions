//
// test.cpp
//
// Copyright (c) 2011 Anton V. Yabchinskiy (arn at users dot berlios dot de)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//


#include <iostream>

#include <Poco/Exception.h>
#include <Poco/Net/HTTPClientSession.h>
#include <Poco/Net/HTTPCredentials.h>
#include <Poco/Net/HTTPRequest.h>
#include <Poco/Net/HTTPResponse.h>
#include <Poco/StreamCopier.h>
#include <Poco/URI.h>

namespace {


bool
isUnathorized(const Poco::Net::HTTPResponse& response)
{
    return response.getStatus() == Poco::Net::HTTPResponse::HTTP_UNAUTHORIZED;
}


void
performRequest(Poco::Net::HTTPClientSession& session,
               Poco::Net::HTTPRequest& request,
               Poco::Net::HTTPResponse& response)
{
    static int n = 1;

    request.write(std::cout << "** Request " << n << " **\n");
    session.sendRequest(request);

    std::istream& stream = session.receiveResponse(response);

    response.write(std::cout << "** Response " << n << " **\n");
    Poco::StreamCopier::copyStream(stream, std::cout);

    ++n;
}


}// namespace


int
main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " URL\n";
        return 1;
    }

    try {
        Poco::URI url(argv[1]);

        std::string username;
        std::string password;

        Poco::Net::HTTPCredentials::extractFromURI(url, username, password);

        Poco::Net::HTTPCredentials credentials(username, password);

        Poco::Net::HTTPClientSession session;
        Poco::Net::HTTPRequest       request;
        Poco::Net::HTTPResponse      response;

        request.setHost(url.getHost(), url.getPort());
        request.setURI(url.getPathEtc());

        session.setHost(url.getHost());
        session.setPort(url.getPort());

        performRequest(session, request, response);
        if (isUnathorized(response)) {
            credentials.authenticate(request, response);
            performRequest(session, request, response);
        }

        credentials.updateAuthInfo(request);
        performRequest(session, request, response);

        credentials.updateAuthInfo(request);
        performRequest(session, request, response);
    } catch (const Poco::Exception& error) {
        std::cerr << error.displayText() << std::endl;
        return 1;
    }

    return 0;
}
