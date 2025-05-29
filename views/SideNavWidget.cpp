#include "SideNavWidget.h"
#include <QVBoxLayout>
#include <QPushButton>
#include <QIcon>
#include <QSizePolicy>
#include <QStyle>

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

    for (int i = 0; i < navItems.size(); ++i) {
        QPushButton *button = createNavButton(navItems[i].text, navItems[i].iconPath);
        layout->addWidget(button);
        if (i < navItems.size() - 1) {
            layout->addSpacing(20);
        }
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

QPushButton* SideNavWidget::createNavButton(const QString &text, const QString &iconPath) {
    QPushButton *button = new QPushButton(text, this);
    button->setIcon(QIcon(iconPath));
    button->setIconSize(QSize(20, 20));
    button->setCheckable(true);
    return button;
}

void SideNavWidget::setActiveTab(const QString &tabName) {
    for (QPushButton *button : findChildren<QPushButton*>()) {
        if (button->text() == tabName) {
            button->setProperty("active", true);
        } else {
            button->setProperty("active", false);
        }
        button->style()->unpolish(button);
        button->style()->polish(button);
        button->update();
    }
}