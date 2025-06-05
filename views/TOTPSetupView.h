#ifndef TOTPSETUPVIEW_H
#define TOTPSETUPVIEW_H

#include <QWidget>
#include <QString>
#include <QPixmap>

class QLabel;
class QLineEdit;
class QPushButton;
class QVBoxLayout;
class QHBoxLayout;

class TOTPController; // Forward declaration

class TOTPSetupView : public QWidget {
    Q_OBJECT

public:
    explicit TOTPSetupView(QWidget *parent = nullptr);
    
    // Methods for controller to interact with view
    void displayQRCode(const QString &qrCodeBase64);
    void showError(const QString &message);
    void clearError();
    void clearCode();
    QString getVerificationCode() const;
    void setController(TOTPController *controller);
    
    // UI state management
    void setSetupInProgress(bool inProgress);

private slots:
    void handleVerifyClicked();
    void handleCancelClicked();
    void onCodeChanged();

private:
    // UI Components
    QLabel *m_titleLabel;
    QLabel *m_instructionLabel;
    QLabel *m_qrCodeLabel;
    QLabel *m_stepLabel;
    QLineEdit *m_codeInput;
    QPushButton *m_verifyButton;
    QPushButton *m_cancelButton;
    QLabel *m_errorLabel;
    
    // Layouts
    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_buttonLayout;
    
    // Controller reference
    TOTPController *m_controller;
    
    void setupUI();
    void loadStyles();
    QPixmap convertBase64ToQRImage(const QString &base64Data);
};

#endif // TOTPSETUPVIEW_H 