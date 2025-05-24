#pragma once

#include <QString>
#include <QUrl>
#include <QIODevice> //for no memory limits
#include "httpC/HttpClient.h"

//this class is used to transfer files over the network, so upload and download
// we're gonna use streaming approach compared to reading the whole file into memory -> this is more efficient and scalable
// so no readall() or readtoend() and writeall() or writetoend(), but streams 
//basically streams files over a TLS-wrapped HTTP connection


class FileTransfer {
public:
    explicit FileTransfer(HttpClient& client);

    /// Streams the file at `localPath` to `uploadUrl`; returns true on HTTP 200.
    bool uploadFile(const QString& localPath, const QUrl& uploadUrl);

    /// Streams from `downloadUrl` and writes directly to `destPath`; returns true on HTTP 200.
    bool downloadFile(const QUrl& downloadUrl, const QString& destPath);

private:
    HttpClient& httpClient_;
};
