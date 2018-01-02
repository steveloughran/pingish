cmake_minimum_required (VERSION 2.6)
project (pingish)
add_executable(pingish main.c)

set(DOXYGEN_GENERATE_HTML NO)
set(DOXYGEN_GENERATE_MAN YES)
find_package(Doxygen)

doxygen_add_docs(
doxygen
${PROJECT_SOURCE_DIR}
COMMENT "Generate man pages"
)
