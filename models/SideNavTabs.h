#pragma once
//pragma once means “Only include this file once, no matter how many times it’s included.”, its the improvement of include guards
#include <QString>
#include <QMap>

enum class SideNavTab {
    OwnedFiles,
    SharedWithMe,
    Inbox
};

struct NavTabInfo {
    QString label;
    QString iconPath;
    QString objectName;
};

inline const QMap<SideNavTab, NavTabInfo> NavTabData = {
    {SideNavTab::OwnedFiles,     {" Owned Files", ":/assets/folder.svg", "ownedFilesButton"}},
    {SideNavTab::SharedWithMe,   {" Shared With Me", ":/assets/shared.svg", "sharedFilesButton"}},
    {SideNavTab::Inbox,          {" Inbox", ":/assets/inbox.svg", "inboxButton"}}
};
