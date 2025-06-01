#include "SideNavController.h"
#include <QPushButton>
#include "../models/SideNavTabs.h"

SideNavController::SideNavController(SideNavWidget *view, QObject *parent)
    : QObject(parent), view(view) {
    connectSignals();
}


void SideNavController::setActiveTab(SideNavTab tab) {
    view->setActiveTab(tab);
}

void SideNavController::setView(SideNavWidget *newView) {
    if (view != newView) {
        view = newView;
        connectSignals();
    }
}

void SideNavController::connectSignals() {
    for (auto it = NavTabData.begin(); it != NavTabData.end(); ++it) {
        SideNavTab tab = it.key();
        const QString &objName = it.value().objectName;
        QPushButton *button = view->findChild<QPushButton*>(objName);
        if (!button) continue;
        switch (tab) {
            case SideNavTab::OwnedFiles:
                connect(button, &QPushButton::clicked, this, &SideNavController::ownedFilesRequested);
                break;
            case SideNavTab::SharedWithMe:
                connect(button, &QPushButton::clicked, this, &SideNavController::sharedFilesRequested);
                break;
            case SideNavTab::Inbox:
                connect(button, &QPushButton::clicked, this, &SideNavController::inboxRequested);
                break;
        }
    }
    //logout button
    QPushButton *logoutBtn = view->findChild<QPushButton*>("logoutButton");
    if (logoutBtn) {
        connect(logoutBtn, &QPushButton::clicked, this, &SideNavController::logoutRequested);
    }
}