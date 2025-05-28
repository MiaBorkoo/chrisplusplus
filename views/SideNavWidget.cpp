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

    for (const NavItem &item : navItems) {
        QPushButton *button = createNavButton(item.text, item.iconPath);
        layout->addWidget(button);
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
    // Find and activate the button with matching text
    for (QPushButton *button : findChildren<QPushButton*>()) {
        if (button->text() == tabName) {
            button->setProperty("active", true);
            button->setStyleSheet(button->styleSheet()); // Force style update
        } else {
            button->setProperty("active", false);
            button->setStyleSheet(button->styleSheet()); // Force style update
        }
    }
}