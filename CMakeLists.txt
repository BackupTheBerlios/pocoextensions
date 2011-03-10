
cmake_minimum_required(VERSION 2.6)

#------------------------------------------------------------------------------
# Project variables

project(PocoExtensions)

set(PocoExtensions_MAJOR_VERSION 1)
set(PocoExtensions_MINOR_VERSION 2)
set(PocoExtensions_PATCH_VERSION 3)
set(PocoExtensions_VERSION
  "${PocoExtensions_MAJOR_VERSION}.${PocoExtensions_MINOR_VERSION}.${PocoExtensions_PATCH_VERSION}")

if(WIN32)
  set(CMAKE_DEBUG_POSTFIX d)
endif(WIN32)

#------------------------------------------------------------------------------
# Compiler flags

if(CMAKE_COMPILER_IS_GNUCXX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wcast-align")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wconversion")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wctor-dtor-privacy")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Weffc++")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wextra")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wfloat-equal")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Winit-self")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wlogical-op")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wmissing-include-dirs")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wold-style-cast")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Woverloaded-virtual")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wpointer-arith")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wredundant-decls")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wshadow")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wsign-conversion")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wwrite-strings")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fno-gnu-keywords")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pedantic")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pipe")
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++98")
endif(CMAKE_COMPILER_IS_GNUCXX)

#------------------------------------------------------------------------------
# Find required packages

find_path(POCO_INCLUDE_DIRS
  NAMES Poco/Foundation.h
  PATHS /usr/include /usr/local/include
  )
include_directories(${POCO_INCLUDE_DIRS})

find_library(POCO_Foundation_LIBRARY
  NAMES PocoFoundation
  PATHS /usr/lib /usr/local/lib
  )

find_library(POCO_Net_LIBRARY
  NAMES PocoNet
  PATHS /usr/lib /usr/local/lib
  )

#------------------------------------------------------------------------------
# Sources

include_directories(${PROJECT_SOURCE_DIR}/include)

set(PocoExtensions_HEADERS
  include/Poco/Net/HTTPAuthenticationParams.h
  include/Poco/Net/HTTPCredentials.h
  include/Poco/Net/HTTPDigestCredentials.h
  include/Poco/Net/Utility.h
  )

set(PocoExtensions_SOURCES
  src/Net/HTTPAuthenticationParams.cpp
  src/Net/HTTPCredentials.cpp
  src/Net/HTTPDigestCredentials.cpp
  src/Net/Utility.cpp
  )

#------------------------------------------------------------------------------
# Targets

add_library(PocoExtensions STATIC ${PocoExtensions_SOURCES})
set_target_properties(PocoExtensions PROPERTIES SOVERSION ${PocoExtensions_VERSION})
target_link_libraries(PocoExtensions ${POCO_Foundation_LIBRARY} ${POCO_Net_LIBRARY})
if(WIN32)
  set_target_properties(PocoExtensions PROPERTIES PREFIX "")
endif(WIN32)

#------------------------------------------------------------------------------
# Installation

install(FILES ${PocoExtensions_HEADERS} DESTINATION include)
install(TARGETS PocoExtensions DESTINATION lib)

#------------------------------------------------------------------------------
# Packaging

include(InstallRequiredSystemLibraries)

set(CPACK_PACKAGE_CONTACT "Anton Yabchinskiy <arn@users.berlios.de>")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Extensions to the POCO C++ library")
set(CPACK_PACKAGE_VERSION_MAJOR ${PocoExtensions_MAJOR_VERSION})
set(CPACK_PACKAGE_VERSION_MINOR ${PocoExtensions_MINOR_VERSION})
set(CPACK_PACKAGE_VERSION_PATCH ${PocoExtensions_PATCH_VERSION})

include(CPack)
