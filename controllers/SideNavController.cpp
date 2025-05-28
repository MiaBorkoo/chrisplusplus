#include "SideNavController.h"
#include <QPushButton>

SideNavController::SideNavController(SideNavWidget *view, QObject *parent)
    : QObject(parent), view(view) {
    connectSignals();
}

void SideNavController::setActiveTab(const QString &tabName) {
    view->setActiveTab(tabName);
}

void SideNavController::setView(SideNavWidget *newView) {
    if (view != newView) {
        view = newView;
        connectSignals();
    }
}

void SideNavController::connectSignals() {
    // Find all navigation buttons and connect their clicked signals
    for (QPushButton *button : view->findChildren<QPushButton*>()) {
        if (button->text() == " Owned Files") {
            connect(button, &QPushButton::clicked, this, &SideNavController::ownedFilesRequested);
        }
        else if (button->text() == " Shared With Me") {
            connect(button, &QPushButton::clicked, this, &SideNavController::sharedFilesRequested);
        }
        else if (button->text() == " Inbox") {
            connect(button, &QPushButton::clicked, this, &SideNavController::inboxRequested);
        }
        else if (button->text() == "Logout") {
            connect(button, &QPushButton::clicked, this, &SideNavController::logoutRequested);
        }
    }
} 