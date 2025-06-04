#ifndef TOTPCONTROLLER_H
#define TOTPCONTROLLER_H

#include <QObject>
#include <QString>

// Forward declarations
class TOTPSetupView;
class TOTPCodeDialog;
class TOTPModel;

class TOTPController : public QObject
{
    Q_OBJECT

public:
    explicit TOTPController(QObject *parent = nullptr);
    void setModel(TOTPModel *model);

public slots:
    void showSetupDialog(const QString &qrCodeBase64);
    void showCodeDialog();

private slots:
    void handleSetupCode(const QString &code);
    void handleLoginCode(const QString &code);
    void handleSetupCancelled();
    void handleCodeCancelled();
    void handleVerificationSuccess();
    void handleVerificationError(const QString &error);

private:
    TOTPModel *m_model;
    TOTPSetupView *m_setupView;
    TOTPCodeDialog *m_codeDialog;

signals:
    void setupCodeEntered(const QString &code);
    void loginCodeEntered(const QString &code);
    void setupCancelled();
    void codeCancelled();
};

#endif // TOTPCONTROLLER_H 