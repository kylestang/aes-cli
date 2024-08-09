option(ENABLE_ASAN "enabling address sanitizer" OFF)
option(ENABLE_UBSAN "enabling undefined behaviour sanitizer" OFF)

if(${ENABLE_ASAN})
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=address")
  set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=address")
endif()

if(${ENABLE_UBSAN})
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS_DEBUG} -fsanitize=undefined")
  set(CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS_DEBUG} -fsanitize=undefined")
endif()
