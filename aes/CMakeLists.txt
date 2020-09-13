add_library(base STATIC base.h base.cpp)
target_link_libraries(base PUBLIC)
add_executable(base_test base_test.cpp)
target_link_libraries(base_test PRIVATE gtest_main base)