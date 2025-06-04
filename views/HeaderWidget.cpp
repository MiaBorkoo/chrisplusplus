#include "HeaderWidget.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

HeaderWidget::HeaderWidget(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_StyledBackground, true);
    setFixedHeight(50);

    QLabel *title = new QLabel("Chrisplusplus");

    m_accountBtn = new QPushButton("Account");
    m_accountBtn->setIcon(QIcon(":/assets/account.svg"));
    m_accountBtn->setIconSize(QSize(20, 20));
    m_accountBtn->setFlat(true);
    m_accountBtn->setCursor(Qt::PointingHandCursor);

    QHBoxLayout *layout = new QHBoxLayout(this);
    layout->setContentsMargins(16, 0, 16, 0);
    layout->addWidget(title);
    layout->addStretch(); // to push the account button to the right
    layout->addWidget(m_accountBtn);
    setLayout(layout);
    
    
}
QPushButton* HeaderWidget::accountButton() const {
    return m_accountBtn;
}