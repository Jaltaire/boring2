if(NOT BORINGSSL_PREFIX OR NOT BORINGSSL_PREFIX_INCLUDE)
  message(FATAL_ERROR "The BoringSSL symbol namespace and header directory must be provided.")
endif()

add_definitions(-DBORINGSSL_PREFIX=${BORINGSSL_PREFIX})
include_directories(${BORINGSSL_PREFIX_INCLUDE})
set(CMAKE_ASM_NASM_FLAGS "${CMAKE_ASM_NASM_FLAGS} -DBORINGSSL_PREFIX=${BORINGSSL_PREFIX}")
