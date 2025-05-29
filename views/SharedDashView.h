#ifndef SHAREDDASHVIEW_H
#define SHAREDDASHVIEW_H

#include <QWidget>
#include <QListWidget>
#include <QLineEdit>
#include <QPushButton>
#include "HeaderWidget.h"
#include "SideNavWidget.h"

class SharedDashView : public QWidget {
    Q_OBJECT

public:
    explicit SharedDashView(QWidget *parent = nullptr);
    QListWidget* getFileList() const;
    SideNavWidget* getSideNav() const;
    QLineEdit* getSearchBar() const;
    void addSharedFile(const QString &fileName, const QString &sharedBy);
    QPushButton* getDownloadButtonForRow(int row) const;

signals:
    void downloadRequested(const QString &fileName);

private:
    HeaderWidget *header;
    SideNavWidget *sideNav;
    QListWidget *fileList;
    QLineEdit *searchBar;
};

#endif // SHAREDDASHVIEW_H