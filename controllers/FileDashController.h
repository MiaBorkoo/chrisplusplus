#ifndef FILEDASHCONTROLLER_H
#define FILEDASHCONTROLLER_H

#include <QObject>
#include <QLineEdit>
#include <QTableWidget>

class FileDashController : public QObject {
    Q_OBJECT

public:
    explicit FileDashController(QLineEdit *searchBar, QTableWidget *fileTable, QObject *parent = nullptr);

signals:
    void searchRequested(const QString &query);
    void fileSelected(const QString &fileName);

private slots:
    void handleSearchInput(const QString &text);
    void handleFileSelection(int row, int column);

private:
    QLineEdit *searchBar;
    QTableWidget *fileTable;
};

#endif // FILEDASHCONTROLLER_Hv