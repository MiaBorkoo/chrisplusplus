#ifndef SHAREDDASHCONTROLLER_H
#define SHAREDDASHCONTROLLER_H

#include <QObject>
#include "../views/SharedDashView.h"
#include "../models/SharedFileModel.h"
#include <memory>

class SharedDashController : public QObject {
    Q_OBJECT
public:
    explicit SharedDashController(SharedDashView *view, std::shared_ptr<SharedFileModel> sharedFileModel, QObject *parent = nullptr);
    
    void setFileService(std::shared_ptr<FileService> fileService);

signals:
    void downloadRequested(const QString &fileName);

public slots:
    void onDownloadSharedFileRequested(const QString &fileId, const QString &displayName);

private slots:
    void handleSharedFileListUpdated(const QList<MvcSharedFileInfo>& files, int totalFiles, int currentPage, int totalPages);
    void handleFileDownloaded(bool success, const QString& fileName);
    void handleError(const QString& error);

private:
    SharedDashView *view;
    std::shared_ptr<SharedFileModel> m_sharedFileModel;
    void connectSignals();
    void loadSharedFiles();
};

#endif // SHAREDDASHCONTROLLER_H 