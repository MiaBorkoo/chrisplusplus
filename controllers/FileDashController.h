#ifndef FILEDASHCONTROLLER_H
#define FILEDASHCONTROLLER_H

#include <QObject>
#include <QMap>
#include <QStringList>
#include <QLineEdit>
#include <QTableWidget>
#include "../views/FilesDashView.h"
#include "AccessController.h"

class FileDashController : public QObject {
    Q_OBJECT
public:
    explicit FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, QObject *parent = nullptr);
    void showAccessDialogForFile(const QString &fileName);

signals:
    void searchRequested(const QString &text);
    void fileSelected(const QString &fileName);

public slots:
    void handleSearch(const QString &text);
    void handleFileSelection(int row, int column);

private:
    QLineEdit *m_searchBar;
    QTableWidget *m_fileTable;
    FilesDashView *m_view;
    QMap<QString, QStringList> m_fileAccess;  // fileName -> list of user emails
};

#endif // FILEDASHCONTROLLER_H