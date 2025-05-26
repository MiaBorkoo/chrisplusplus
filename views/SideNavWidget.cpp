#include "SideNavWidget.h"
#include <QVBoxLayout>
#include <QPushButton>
#include <QIcon>
#include <QSizePolicy>

SideNavWidget::SideNavWidget(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_StyledBackground, true);
    setFixedWidth(200);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 16, 8, 16);
    layout->setSpacing(8);
    

    struct NavItem {
        QString text;
        QString iconPath;
    };

    QList<NavItem> navItems = {
        {" Owned Files", ":/assets/folder.svg"},
        {" Shared With Me", ":/assets/shared.svg"},
        {" Inbox", ":/assets/inbox.svg"}
    };

    for (const auto &item : navItems) {
        QPushButton *btn = new QPushButton(item.text);
        btn->setIcon(QIcon(item.iconPath));
        btn->setIconSize(QSize(22, 22));
        btn->setFlat(true);
        btn->setCursor(Qt::PointingHandCursor);
        btn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        layout->addWidget(btn);
    }

    layout->addStretch();

    QPushButton *logoutBtn = new QPushButton("Logout");
    logoutBtn->setIcon(QIcon(":/assets/logout.svg")); 
    logoutBtn->setIconSize(QSize(20, 20));
    logoutBtn->setFlat(true);
    logoutBtn->setCursor(Qt::PointingHandCursor);
    logoutBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    layout->addWidget(logoutBtn);

    setLayout(layout);
}