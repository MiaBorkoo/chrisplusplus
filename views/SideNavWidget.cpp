#include "SideNavWidget.h"
#include <QVBoxLayout>
#include <QButtonGroup>
#include <QStyle>

SideNavWidget::SideNavWidget(QWidget *parent) : QWidget(parent) {
    setAttribute(Qt::WA_StyledBackground, true);
    setFixedWidth(200);

    QVBoxLayout *layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 16, 8, 16);
    layout->setSpacing(8);

    QButtonGroup *group = new QButtonGroup(this);
    group->setExclusive(true);

    for (auto tab : NavTabData.keys()) {
        const auto &info = NavTabData[tab];
        QPushButton *button = createNavButton(info);
        button->setObjectName(info.objectName);
        button->setCheckable(true);
        group->addButton(button);
        navButtons[tab] = button;
        layout->addWidget(button);
    }

    layout->addSpacing(20);
    layout->addStretch();

    QPushButton *logoutBtn = new QPushButton("Logout");
    logoutBtn->setIcon(QIcon(":/assets/logout.svg"));
    logoutBtn->setIconSize(QSize(20, 20));
    logoutBtn->setFlat(true);
    logoutBtn->setCursor(Qt::PointingHandCursor);
    logoutBtn->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    logoutBtn->setObjectName("logoutButton");
    layout->addWidget(logoutBtn);

    setLayout(layout);
}

QPushButton* SideNavWidget::createNavButton(const NavTabInfo &info) {
    QPushButton *button = new QPushButton(info.label, this);
    button->setIcon(QIcon(info.iconPath));
    button->setIconSize(QSize(20, 20));
    return button;
}

void SideNavWidget::setActiveTab(SideNavTab tab) {
    //looping through all navigation buttons in the side nav
    for (auto it = navButtons.begin(); it != navButtons.end(); ++it) {
        bool isActive = (it.key() == tab);//checks if this button corresponds to the tab we want to activate
        it.value()->setProperty("active", isActive); //sets true or false for the active tab
        it.value()->style()->unpolish(it.value()); //forces the style sheet to be re-applied to update the UI
        it.value()->style()->polish(it.value());
        it.value()->update(); //this will trigger a repaint to ensure the update is instant
    }
}