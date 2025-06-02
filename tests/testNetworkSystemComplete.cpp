/**********************************************************************
 ChrisPlusPlus – Async network system test
 ---------------------------------------------------------------------
 Builds a small Qt GUI that exercises:

   • SSLContext + SSLConnection
   • HttpClient (sendRequest + 128 KB chunk optimisation)
   • NEW async FileTransfer (upload & download)

 Requires:
   • Qt 6 (Core, Widgets, Network, Concurrent)
   • chrisplusplus libraries already built/linked

 *********************************************************************/

#include <QApplication>
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QPushButton>
#include <QLabel>
#include <QProgressBar>
#include <QTextEdit>
#include <QFileDialog>
#include <QDir>
#include <QTimer>
#include <QFile>
#include <QFileInfo>
#include <QFont>
#include <QtConcurrent/QtConcurrent>      // for future-proofing
#include <iostream>

// === ChrisPlusPlus headers ===
#include "../sockets/SSLContext.h"
#include "../sockets/SSLConnection.h"
#include "../httpC/HttpClient.h"
#include "../httpC/HttpRequest.h"
#include "../httpC/HttpResponse.h"
#include "../fileIO/fileTransfer.h"      // your new async impl.

class TestHarness : public QWidget
{
    Q_OBJECT

public:
    TestHarness()
    {
        setWindowTitle("ChrisPlusPlus – Async network test suite");
        resize(880, 680);
        setupUi();

        // --- SSL init ---
        SSLContext::initializeOpenSSL();
        ssl_         = std::make_unique<SSLContext>();
        fileTx_      = std::make_shared<FileTransfer>(*ssl_);
        fileTx_->setServer("httpbin.org", "443");          // public echo service
        fileTx_->setChunkSize(512 * 1024);  // 512KB chunks (4x faster!)

        connect(fileTx_.get(), &FileTransfer::progressUpdated,
                this,         &TestHarness::onProgress);
        connect(fileTx_.get(), &FileTransfer::uploadCompleted,
                this,         &TestHarness::onUploadDone);
        connect(fileTx_.get(), &FileTransfer::downloadCompleted,
                this,         &TestHarness::onDownloadDone);

        log("✅ SSLContext initialised, TLS ≥1.2 enforced");
        log("✅ HttpClient + FileTransfer ready (async)");
    }

private slots:
    // ------------ individual tests ------------
    void testSsl()
    {
        section("SSL / TLS foundation");

        try {
            SSLConnection conn(*ssl_, "httpbin.org", "443");
            conn.setTimeout(10);

            std::string ping =
                "GET /bytes/1 HTTP/1.1\r\n"
                "Host: httpbin.org\r\nConnection: close\r\n\r\n";

            conn.send(ping.data(), ping.size());
            char buf[16];
            ssize_t n = conn.receive(buf, sizeof(buf));
            log(QString("✅ Received %1 byte(s) over TLS").arg(n));
            pass();
        } catch (const std::exception& e) {
            fail(e.what());
        }
    }

    void testHttp()
    {
        section("HTTP protocol layer");

        try {
            HttpClient hc(*ssl_, "httpbin.org", "443");
            hc.setChunkSize(128*1024);

            HttpRequest req;
            req.method = "GET";
            req.path   = "/json";
            req.headers["User-Agent"] = "CPP-Tester/1.0";

            HttpResponse r = hc.sendRequest(req);
            log(QString("✅ HTTP status %1").arg(r.statusCode));
            log(QString("   Body preview: %1...")
                    .arg(QString::fromStdString(r.body).left(80)));
            pass();
        } catch (const std::exception& e) {
            fail(e.what());
        }
    }

    void testUpload()
    {
        section("Async upload (user-selected file)");

        // Let user pick any file
        QString path = QFileDialog::getOpenFileName(
            this, 
            "Choose file to upload", 
            QDir::homePath(), 
            "All Files (*.*)"
        );
        
        if (path.isEmpty()) {
            log("❌ No file selected");
            return;
        }
        
        QFileInfo info(path);
        log(QString("📁 Selected: %1 (%2)").arg(info.fileName()).arg(format(info.size())));
        tmpUpload_ = path;

        fileTx_->uploadFileAsync(path, "/post", 2);
        log("🚀 uploadFileAsync() called – GUI still responsive");
    }

    void testDownload()
    {
        section("Async download (httpbin /json)");

        tmpDownload_ = QDir::temp().filePath("cpp_async_dl.json");
        fileTx_->downloadFileAsync("/json", tmpDownload_, 2);
        log("🚀 downloadFileAsync() called");
    }

    void runAll()
    {
        testSsl();
        QTimer::singleShot( 800, this, &TestHarness::testHttp);
        QTimer::singleShot(1600, this, &TestHarness::testUpload);
        QTimer::singleShot(5500, this, &TestHarness::testDownload);
    }

    // ------------ async callbacks ------------
    void onProgress(qint64 done, qint64 total)
    {
        double pct = total ? double(done)*100/total : 0;
        progress_->setVisible(true);
        progress_->setValue(int(pct));
        log(QString("   … %1 % (%2 / %3)")
             .arg(pct,0,'f',1)
             .arg(format(done))
             .arg(format(total)));
    }

    void onUploadDone(bool ok, const TransferResult& r)
    {
        progress_->setVisible(false);
        if (ok)  { pass("Upload ok, bytes="+format(r.bytesTransferred)); }
        else     { fail(r.errorMessage); }
    }

    void onDownloadDone(bool ok, const TransferResult& r)
    {
        progress_->setVisible(false);
        if (ok)  { pass("Download ok, bytes="+format(r.bytesTransferred)); }
        else     { fail(r.errorMessage); }
        if (!tmpDownload_.isEmpty()) QFile::remove(tmpDownload_);
    }

private:
    // ------------ UI helpers ------------
    void setupUi()
    {
        auto *lay = new QVBoxLayout(this);

        auto btnRow = new QHBoxLayout;
        addBtn(btnRow, "SSL",        &TestHarness::testSsl);
        addBtn(btnRow, "HTTP",       &TestHarness::testHttp);
        addBtn(btnRow, "Upload",     &TestHarness::testUpload);
        addBtn(btnRow, "Download",   &TestHarness::testDownload);
        addBtn(btnRow, "Run All ▶",  &TestHarness::runAll);
        lay->addLayout(btnRow);

        progress_ = new QProgressBar;
        progress_->setVisible(false);
        lay->addWidget(progress_);

        logBox_ = new QTextEdit;
        logBox_->setReadOnly(true);
        logBox_->setFont(QFont("Menlo",10));
        lay->addWidget(logBox_);
    }

    void addBtn(QHBoxLayout* row, const QString& txt, void (TestHarness::*slot)())
    {
        auto *b = new QPushButton(txt);
        connect(b,&QPushButton::clicked,this,slot);
        row->addWidget(b);
    }

    void section(const QString& t)      { log(QString("\n=== %1 ===").arg(t)); }
    void log(const QString& m)          { logBox_->append(m); std::cout<<m.toStdString()<<'\n'; }
    void pass(const QString& m="OK")    { log("✅ "+m); }
    void fail(const QString& m)         { log("❌ "+m); }

    static QString format(qint64 b)
    {
        if (b<1024)               return QString::number(b)+" B";
        if (b<1024*1024)          return QString::number(b/1024.0,'f',1)+" KB";
        return QString::number(b/1024.0/1024,'f',1)+" MB";
    }

    // ------------ members ------------
    std::unique_ptr<SSLContext>  ssl_;
    std::shared_ptr<FileTransfer> fileTx_;
    QTextEdit*   logBox_;
    QProgressBar* progress_;
    QString      tmpUpload_, tmpDownload_;
};

#include "testNetworkSystemComplete.moc" 

int main(int argc, char* argv[])
{
    QApplication a(argc, argv);
    TestHarness   w;
    w.show();
    return a.exec();
}
