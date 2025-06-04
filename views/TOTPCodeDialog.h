#ifndef TOTPCODEDIALOG_H
#define TOTPCODEDIALOG_H

#include <QDialog>
#include <QString>

class QLabel;
class QLineEdit;
class QPushButton;
class QVBoxLayout;
class QHBoxLayout;

class TOTPCodeDialog : public QDialog {
    Q_OBJECT

public:
    explicit TOTPCodeDialog(QWidget *parent = nullptr);
    
    // Methods for controller interaction
    QString getCode() const;
    void showError(const QString &message);
    void clearError();
    void clearCode();
    void setVerificationInProgress(bool inProgress);

signals:
    void codeEntered(const QString &code);

private slots:
    void handleVerifyClicked();
    void handleCancelClicked();
    void onCodeChanged();

private:
    // UI Components
    QLabel *m_titleLabel;
    QLabel *m_instructionLabel;
    QLineEdit *m_codeInput;
    QPushButton *m_verifyButton;
    QPushButton *m_cancelButton;
    QLabel *m_errorLabel;
    
    // Layouts
    QVBoxLayout *m_mainLayout;
    QHBoxLayout *m_buttonLayout;
    
    void setupUI();
    void styleComponents();
};

#endif // TOTPCODEDIALOG_H 