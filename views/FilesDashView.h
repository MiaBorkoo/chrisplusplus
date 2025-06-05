#ifndef FILESDASHVIEW_H
#define FILESDASHVIEW_H

#include <QWidget>
#include <QLineEdit>
#include <QTableWidget>
#include "HeaderWidget.h"
#include "SideNavWidget.h"
#include "AccountSection.h"
#include "../controllers/AccountController.h"

class QPushButton;

class FilesDashView : public QWidget {
    Q_OBJECT
public:
    explicit FilesDashView(QWidget *parent = nullptr);
    QLineEdit* getSearchBar() const;
    QTableWidget* getFileTable() const;
    SideNavWidget* getSideNav() const;
    HeaderWidget* getHeader() const;
    void addFileRow(const QString &name, const QString &size, const QString &date, const QString &fileId = "");
    void clearTable();

private:
    HeaderWidget *header;
    SideNavWidget *sideNav;
    QLineEdit *searchBar;
    QTableWidget *fileTable;
    AccountSection *accountSection;
    AccountController *accountController;
    QPushButton *uploadButton;

signals:
    void fileOpenRequested(const QString &fileName);
    void uploadRequested();
    void accessRequested(const QString &fileId, const QString &displayName);
    void deleteRequested(const QString &fileId, const QString &displayName);
    void downloadRequested(const QString &fileId, const QString &displayName);
};

#endif // FILESDASHVIEW_H
