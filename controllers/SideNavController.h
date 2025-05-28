#ifndef SIDENAVCONTROLLER_H
#define SIDENAVCONTROLLER_H

#include <QObject>
#include <QString>
#include "../views/SideNavWidget.h"

class SideNavController : public QObject {
    Q_OBJECT
public:
    explicit SideNavController(SideNavWidget *view, QObject *parent = nullptr);
    void setActiveTab(const QString &tabName);
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