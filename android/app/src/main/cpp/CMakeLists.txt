# For more information about using CMake with Android Studio, read the
# documentation: https://d.android.com/studio/projects/add-native-code.html.
# For more examples on how to use CMake, see https://github.com/android/ndk-samples.

# Sets the minimum CMake version required for this project.
cmake_minimum_required(VERSION 3.22.1)

# Declares the project name. The project name can be accessed via ${ PROJECT_NAME},
# Since this is the top level CMakeLists.txt, the project name is also accessible
# with ${CMAKE_PROJECT_NAME} (both CMake variables are in-sync within the top level
# build script scope).
project("hp39gii")

# Creates and names a library, sets it as either STATIC
# or SHARED, and provides the relative paths to its source code.
# You can define multiple libraries, and CMake builds them for you.
# Gradle automatically packages shared libraries with your APK.
#
# In this top level CMakeLists.txt, ${CMAKE_PROJECT_NAME} is used to define
# the target library name; in the sub-module's CMakeLists.txt, ${PROJECT_NAME}
# is preferred for the same purpose.
#
# In order to load a library into your app from Java/Kotlin, you must call
# System.loadLibrary() and pass the name of the library defined here;
# for GameActivity/NativeActivity derived applications, the same library name must be
# used in the AndroidManifest.xml file.
add_library(${CMAKE_PROJECT_NAME} SHARED
        # List C/C++ source files with relative paths to this CMakeLists.txt.
        native-lib.cpp)

# --- Unicorn Engine (x86 guest) as prebuilt static libs -------------------
# QEMU's configure step can't run on a Windows host, so Unicorn is
# cross-compiled in a Linux Docker container (see android/docker/) and the
# resulting static archives are checked into prebuilt/<abi>/. Headers live in
# prebuilt/include/. Build them with:  docker build + docker run  (see README).
set(UNICORN_DIR ${CMAKE_CURRENT_SOURCE_DIR}/prebuilt)
file(GLOB UNICORN_LIBS CONFIGURE_DEPENDS ${UNICORN_DIR}/${ANDROID_ABI}/*.a)
if(NOT UNICORN_LIBS)
    message(FATAL_ERROR
        "No Unicorn static libs found in ${UNICORN_DIR}/${ANDROID_ABI}. "
        "Build them first: see android/docker/README or build-unicorn.sh.")
endif()

target_include_directories(${CMAKE_PROJECT_NAME} PRIVATE
        ${UNICORN_DIR}/include)

# Specifies libraries CMake should link to your target library.
# The two Unicorn archives reference each other, so group them so the linker
# resolves symbols across both regardless of order.
target_link_libraries(${CMAKE_PROJECT_NAME}
        -Wl,--start-group ${UNICORN_LIBS} -Wl,--end-group
        android
        log)