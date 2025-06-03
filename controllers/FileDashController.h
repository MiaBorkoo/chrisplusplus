#ifndef FILEDASHCONTROLLER_H
#define FILEDASHCONTROLLER_H

#include <QObject>
#include <QMap>
#include <QStringList>
#include <QLineEdit>
#include <QTableWidget>
#include <QList>
#include "../views/FilesDashView.h"
#include "AccessController.h"
#include <QPushButton>
#include <QIcon>
#include <QSize>

class FileDashController : public QObject {
    Q_OBJECT
public:
    struct FileRow {
        QString name;
        QString size;
        QString date;
    };

    explicit FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, QObject *parent = nullptr);
    void showAccessDialogForFile(const QString &fileName);
    void repopulateTable();

signals:
    void searchRequested(const QString &text);
    void fileSelected(const QString &fileName);
    void accessChanged(const QString &fileName, const QStringList &newAcl);

public slots:
    void handleSearch(const QString &text);
    void handleFileSelection(int row, int column);
    void onDeleteFileRequested(const QString &fileName);

private:
    QLineEdit *m_searchBar;
    QTableWidget *m_fileTable;
    FilesDashView *m_view;
    QMap<QString, QStringList> m_fileAccess;  // fileName -> list of user emails
    QList<FileRow> m_files;
};

#endif // FILEDASHCONTROLLER_H