#include "HeaderWidget.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>

HeaderWidget::HeaderWidget(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_StyledBackground, true);
    setFixedHeight(50);

    QLabel *title = new QLabel("Chrisplusplus");

    QPushButton *accountBtn = new QPushButton("Account");
    accountBtn->setIcon(QIcon(":/assets/account.svg"));
    accountBtn->setIconSize(QSize(20, 20));
    accountBtn->setFlat(true);
    accountBtn->setCursor(Qt::PointingHandCursor);

    QHBoxLayout *layout = new QHBoxLayout(this);
    layout->setContentsMargins(16, 0, 16, 0);
    layout->addWidget(title);
    layout->addStretch(); // to push the account button to the right
    layout->addWidget(accountBtn);
    setLayout(layout);
    
}