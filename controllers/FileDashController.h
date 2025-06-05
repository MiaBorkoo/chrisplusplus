#ifndef FILEDASHCONTROLLER_H
#define FILEDASHCONTROLLER_H

#include <QObject>
#include <QMap>
#include <QStringList>
#include <QLineEdit>
#include <QTableWidget>
#include <QList>
#include "../views/FilesDashView.h"
#include "../models/FileModel.h"
#include <QPushButton>
#include <QIcon>
#include <QSize>
#include <memory>

class FileDashController : public QObject {
    Q_OBJECT
public:
    struct FileRow {
        QString name;
        QString size;
        QString date;
    };

    explicit FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, std::shared_ptr<FileModel> fileModel, QObject *parent = nullptr);
    void repopulateTable();
    void setFileService(std::shared_ptr<FileService> fileService);

signals:
    void searchRequested(const QString &text);
    void fileSelected(const QString &fileName);

public slots:
    void handleSearch(const QString &text);
    void handleFileSelection(int row, int column);
    void onDeleteFileRequested(const QString &fileName);

private:
    QLineEdit *m_searchBar;
    QTableWidget *m_fileTable;
    FilesDashView *m_view;
    QList<FileRow> m_files;
    std::shared_ptr<FileModel> m_fileModel;
};

#endif // FILEDASHCONTROLLER_H