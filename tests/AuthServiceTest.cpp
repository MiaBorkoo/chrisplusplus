#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include "../services/auth/AuthService.h"
#include "../network/Client.h"

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

class MockClient : public Client {
public:
    MockClient() : Client("", "") {}
    MOCK_METHOD(void, sendRequest, (const QString&, const QString&, const QJsonObject&), (override));
};

class AuthServiceTest : public ::testing::Test {
protected:
    MockClient* mockClient;
    AuthService* authService;

    void SetUp() override {
        mockClient = new MockClient();
        authService = new AuthService(mockClient);
    }

    void TearDown() override {
        delete authService;
        delete mockClient;
    }
};

TEST_F(AuthServiceTest, LoginSuccess) {
    QJsonObject response;
    response["token"] = "mock_token";
    EXPECT_CALL(*mockClient, sendRequest(_, _, _))
        .WillOnce(Invoke([this](const QString&, const QString&, const QJsonObject&) {
            emit mockClient->responseReceived(200, response);
        }));

    EXPECT_SIGNAL(authService->loginCompleted(true, "mock_token"));
    authService->login("test_user", "test_auth_key");
}

TEST_F(AuthServiceTest, LoginFailure) {
    QJsonObject response;
    response["error"] = "Invalid credentials";
    EXPECT_CALL(*mockClient, sendRequest(_, _, _))
        .WillOnce(Invoke([this](const QString&, const QString&, const QJsonObject&) {
            emit mockClient->responseReceived(401, response);
        }));

    EXPECT_SIGNAL(authService->loginCompleted(false, ""));
    EXPECT_SIGNAL(authService->errorOccurred("Invalid credentials"));
    authService->login("test_user", "wrong_auth_key");
}

TEST_F(AuthServiceTest, RegistrationSuccess) {
    QJsonObject response;
    EXPECT_CALL(*mockClient, sendRequest(_, _, _))
        .WillOnce(Invoke([this](const QString&, const QString&, const QJsonObject&) {
            emit mockClient->responseReceived(200, response);
        }));

    EXPECT_SIGNAL(authService->registrationCompleted(true));
    authService->registerUser("test_user", "auth_salt", "enc_salt", "auth_key", "encrypted_mek");
}

TEST_F(AuthServiceTest, RegistrationFailure) {
    QJsonObject response;
    response["error"] = "Registration failed";
    EXPECT_CALL(*mockClient, sendRequest(_, _, _))
        .WillOnce(Invoke([this](const QString&, const QString&, const QJsonObject&) {
            emit mockClient->responseReceived(400, response);
        }));

    EXPECT_SIGNAL(authService->registrationCompleted(false));
    EXPECT_SIGNAL(authService->errorOccurred("Registration failed"));
    authService->registerUser("test_user", "auth_salt", "enc_salt", "auth_key", "encrypted_mek");
}

TEST_F(AuthServiceTest, ChangePasswordSuccess) {
    QJsonObject response;
    EXPECT_CALL(*mockClient, sendRequest(_, _, _))
        .WillOnce(Invoke([this](const QString&, const QString&, const QJsonObject&) {
            emit mockClient->responseReceived(200, response);
        }));

    EXPECT_SIGNAL(authService->passwordChangeCompleted(true));
    authService->changePassword("test_user", "old_auth_key", "new_auth_key", "new_encrypted_mek");
}

TEST_F(AuthServiceTest, ChangePasswordFailure) {
    QJsonObject response;
    response["error"] = "Password change failed";
    EXPECT_CALL(*mockClient, sendRequest(_, _, _))
        .WillOnce(Invoke([this](const QString&, const QString&, const QJsonObject&) {
            emit mockClient->responseReceived(400, response);
        }));

    EXPECT_SIGNAL(authService->passwordChangeCompleted(false));
    EXPECT_SIGNAL(authService->errorOccurred("Password change failed"));
    authService->changePassword("test_user", "old_auth_key", "new_auth_key", "new_encrypted_mek");
}