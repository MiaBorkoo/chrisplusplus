#ifndef SIDENAVCONTROLLER_H
#define SIDENAVCONTROLLER_H

#include <QObject>
#include "../views/SideNavWidget.h"
#include "../models/SideNavTabs.h"

class SideNavController : public QObject {
    Q_OBJECT
public:
    explicit SideNavController(SideNavWidget *view, QObject *parent = nullptr);
    void setActiveTab(SideNavTab tab);
    void setView(SideNavWidget *newView);

signals:
    void ownedFilesRequested();
    void sharedFilesRequested();
    void inboxRequested();
    void logoutRequested();

private:
    SideNavWidget *view;
    void connectSignals();
};

#endif // SIDENAVCONTROLLER_H 