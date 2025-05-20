include("C:/Users/jogen/MyRepos/Epic/chrisplusplus/build/.qt/QtDeploySupport.cmake")
include("${CMAKE_CURRENT_LIST_DIR}/LoginForm-plugins.cmake" OPTIONAL)
set(__QT_DEPLOY_I18N_CATALOGS "qtbase")

qt6_deploy_runtime_dependencies(
    EXECUTABLE C:/Users/jogen/MyRepos/Epic/chrisplusplus/build/LoginForm.exe
    GENERATE_QT_CONF
)
