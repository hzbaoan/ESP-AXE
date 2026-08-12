idf_component_register(SRCS
                        "unit_test_all.c"
                        "asic_test_stubs.c"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES asic stratum)

target_include_directories(${COMPONENT_LIB} PRIVATE
                           "${CMAKE_CURRENT_SOURCE_DIR}/../../main"
                           "${CMAKE_CURRENT_SOURCE_DIR}/../../main/tasks")
