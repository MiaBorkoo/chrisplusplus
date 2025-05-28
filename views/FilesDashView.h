#ifndef FILESDASHVIEW_H
#define FILESDASHVIEW_H

#include <QWidget>
#include <QLineEdit>
#include <QTableWidget>
#include "HeaderWidget.h"
#include "SideNavWidget.h"

class FilesDashView : public QWidget {
    Q_OBJECT
public:
    explicit FilesDashView(QWidget *parent = nullptr);
    QLineEdit* getSearchBar() const;
    QTableWidget* getFileTable() const;
    SideNavWidget* getSideNav() const;

private:
    HeaderWidget *header;
    SideNavWidget *sideNav;
    QLineEdit *searchBar;
    QTableWidget *fileTable;

signals:
    void fileOpenRequested(const QString &fileName);
    void uploadRequested();
};

#endif // FILESDASHVIEW_H
