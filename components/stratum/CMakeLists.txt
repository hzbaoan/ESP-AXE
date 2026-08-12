idf_component_register(
SRCS
    "utils.c"
    "mining.c"
    "stratum_api.c"
    "stratum_v2.c"
                    
INCLUDE_DIRS
    "include"

REQUIRES
    "json"
    "mbedtls"
    "app_update"
)
