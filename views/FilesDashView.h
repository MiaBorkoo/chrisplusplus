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
    void addFileRow(const QString &name, const QString &size, const QString &date);
    void clearTable();

private:
    HeaderWidget *m_header;
    SideNavWidget *m_sideNav;
    QLineEdit *m_searchBar;
    QTableWidget *m_fileTable;
    AccountSection *accountSection;
    AccountController *accountController;
    QPushButton *m_uploadButton;

signals:
    void fileOpenRequested(const QString &fileName);
    void uploadRequested();
    void accessRequested(const QString &fileName);
    void deleteRequested(const QString &fileName);
    void downloadRequested(const QString &fileName);

};

#endif // FILESDASHVIEW_H
