#pragma once

#include <QObject>
#include <QString>
#include "../views/SignUpView.h"
#include "../models/SignUpModel.h"
#include "../services/auth/ValidationService.h"
#include <memory>

class SignUpController : public QObject {
    Q_OBJECT
public:
    explicit SignUpController(SignUpView *view, std::shared_ptr<SignUpModel> model, QObject *parent = nullptr);

public slots:
    void onSignUpClicked(const QString &username, const QString &password, const QString &confirmPassword);

private slots:
    void handleRegistrationSuccess();
    void handleRegistrationError(const QString &error);

signals:
    void registrationCompleted();
    void registrationSuccessful();
    void registrationFailed(const QString& error);

private:
    SignUpView *view;
    std::shared_ptr<SignUpModel> m_model;
    ValidationService m_validationService;
};
