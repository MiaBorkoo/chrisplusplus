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
    
    //methods for controller to update the view
    void updateUserList(const QStringList &users);
    QString getFileName() const;

signals:
    void addUserRequested(const QString &fileName, const QString &userName);
    void revokeAccessRequested(const QString &fileName, const QString &userName);

private slots:
    void onAddUserClicked();

private:
    QString m_fileName;
    QTableWidget *m_userTable;
    QPushButton *m_addUserButton;
    QLineEdit *m_emailInput;
    void setupUI(const QStringList &users);
};

#endif // ACCESSDIALOG_H