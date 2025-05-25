#pragma once
#include "../ApiService.h"
#include <QString>

class IFileService : public ApiService {
    Q_OBJECT

public:
    virtual ~IFileService() = default;

    virtual void uploadFile(const QString& filename, const QString& fileData) = 0;
    virtual void shareFile(const QString& filename, const QString& shareData) = 0;
    virtual void deleteFile(const QString& filename) = 0;
    virtual void getFile(const QString& filename) = 0;
};