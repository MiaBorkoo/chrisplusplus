#ifndef SHAREDDASHVIEW_H
#define SHAREDDASHVIEW_H

#include <QWidget>
#include <QListWidget>
#include <QLineEdit>
#include "HeaderWidget.h"
#include "SideNavWidget.h"

class SharedDashView : public QWidget {
    Q_OBJECT

public:
    explicit SharedDashView(QWidget *parent = nullptr);
    QListWidget* getFileList() const;
    SideNavWidget* getSideNav() const;
    QLineEdit* getSearchBar() const;

signals:
    void fileOpenRequested(const QString &fileName);

private:
    HeaderWidget *header;
    SideNavWidget *sideNav;
    QListWidget *fileList;
    QLineEdit *searchBar;
};

#endif // SHAREDDASHVIEW_H