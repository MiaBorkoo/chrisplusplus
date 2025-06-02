include("/Users/alisiakazimierek/MyRepos/chrisplusplus/.qt/QtDeploySupport.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/ChrisPlusPlus-plugins.cmake" OPTIONAL)
set(__QT_DEPLOY_I18N_CATALOGS "qtbase")

qt6_deploy_runtime_dependencies(
    EXECUTABLE ChrisPlusPlus.app
)
