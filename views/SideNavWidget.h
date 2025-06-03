#ifndef SIDENAVWIDGET_H
#define SIDENAVWIDGET_H

#include <QWidget>
#include <QPushButton>
#include "../models/SideNavTabs.h"

class SideNavWidget : public QWidget {
    Q_OBJECT
public:
    explicit SideNavWidget(QWidget *parent = nullptr);
    void setActiveTab(SideNavTab tab);

private:
    QPushButton* createNavButton(const NavTabInfo &info);
    QMap<SideNavTab, QPushButton*> navButtons;
};

#endif // SIDENAVWIDGET_H