#ifndef ACCESSDIALOG_H
#define ACCESSDIALOG_H

#include <QDialog>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QLineEdit>

class AccessDialog : public QDialog {
    Q_OBJECT
public:
    explicit AccessDialog(const QString &fileName, const QStringList &users, QWidget *parent = nullptr);
    
    // Getters for UI elements
    QTableWidget* getAccessTable() const;
    QPushButton* getAddUserButton() const;
    
    // Public methods for controller to update the view
    void updateUserList(const QStringList &users);
    void clearUserList();
    QString getFileName() const;

signals:
    void addUserRequested(const QString &fileName, const QString &userName);
    void revokeAccessRequested(const QString &fileName, const QString &userName);

private slots:
    void onAddUserClicked();
    void onRevokeClicked();

private:
    QString m_fileName;
    QTableWidget *m_userTable;
    QPushButton *m_addUserButton;
    QLineEdit *m_emailInput;
    void setupUI(const QStringList &users);
};

#endif // ACCESSDIALOG_H