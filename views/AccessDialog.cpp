#include "AccessDialog.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QTableWidget>
#include <QHeaderView>
#include <QMessageBox>

AccessDialog::AccessDialog(const QString &fileName, const QStringList &users, QWidget *parent)
    : QDialog(parent), m_fileName(fileName)
{
    setWindowTitle(tr("Manage Access: %1").arg(fileName));
    setupUI(users);
}

void AccessDialog::setupUI(const QStringList &users) {
    QVBoxLayout *mainLayout = new QVBoxLayout(this);
    m_userTable = new QTableWidget(this);
    m_userTable->setColumnCount(2);
    m_userTable->setHorizontalHeaderLabels({"Username", "Revoke"});
    m_userTable->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    m_userTable->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_userTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    mainLayout->addWidget(m_userTable);

    QHBoxLayout *addLayout = new QHBoxLayout();
    m_emailInput = new QLineEdit(this);
    m_emailInput->setPlaceholderText("Enter username...");
    m_addUserButton = new QPushButton("Add User", this);
    addLayout->addWidget(m_emailInput);
    addLayout->addWidget(m_addUserButton);
    mainLayout->addLayout(addLayout);

    connect(m_addUserButton, &QPushButton::clicked, this, &AccessDialog::onAddUserClicked);

    updateUserList(users);
}

void AccessDialog::updateUserList(const QStringList &users) {
    //remving all widgets from the table to prevent stacking
    for (int row = 0; row < m_userTable->rowCount(); ++row) {
        QWidget *w = m_userTable->cellWidget(row, 1);
        if (w) {
            m_userTable->removeCellWidget(row, 1);
            delete w;
        }
    }
    m_userTable->clearContents();
    m_userTable->setRowCount(users.size());
    for (int i = 0; i < users.size(); ++i) {
        m_userTable->setItem(i, 0, new QTableWidgetItem(users[i]));
        QPushButton *revokeBtn = new QPushButton("Revoke");
        revokeBtn->setProperty("userName", users[i]);
        m_userTable->setCellWidget(i, 1, revokeBtn);
        connect(revokeBtn, &QPushButton::clicked, this, [this, user=users[i]]() {
            emit revokeAccessRequested(m_fileName, user);
        });
    }
}

QString AccessDialog::getFileName() const {
    return m_fileName;
}

void AccessDialog::onAddUserClicked() {
    QString userName = m_emailInput->text().trimmed();
    emit addUserRequested(m_fileName, userName);
    m_emailInput->clear();
}

