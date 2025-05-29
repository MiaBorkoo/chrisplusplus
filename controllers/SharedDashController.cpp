#include "SharedDashController.h"
#include <QListWidget>
#include <QListWidgetItem>
#include <QLineEdit>
#include <QLabel>
#include <QPushButton>

SharedDashController::SharedDashController(SharedDashView *view, QObject *parent)
    : QObject(parent), view(view) {
    // Placeholder data for shared files (move from view)
    struct SharedFile { QString name; QString sharedBy; };
    QList<SharedFile> sharedFiles = {
        {"ProjectPlan.docx", "user1@example.com"},
        {"Budget2025.xlsx", "user2@example.com"},
        {"MeetingNotes.pdf", "user3@example.com"},
        {"DesignMockup.png", "user1@example.com"}
    };
    for (int i = 0; i < sharedFiles.size(); ++i) {
        const auto &file = sharedFiles[i];
        view->addSharedFile(file.name, file.sharedBy);
        QPushButton *downloadBtn = view->getDownloadButtonForRow(i);
        if (downloadBtn) {
            connect(downloadBtn, &QPushButton::clicked, this, [this, file]() {
                emit downloadRequested(file.name);
            });
        }
    }
    connectSignals();
}

void SharedDashController::connectSignals() {
    connect(view->getSearchBar(), &QLineEdit::textChanged, this, [this](const QString &query) {
        QListWidget *list = view->getFileList();
        for (int i = 0; i < list->count(); ++i) {
            QListWidgetItem *item = list->item(i);
            QWidget *widget = list->itemWidget(item);
            QLabel *fileLabel = widget->findChild<QLabel*>("sharedFileLabel");
            bool match = fileLabel && fileLabel->text().contains(query, Qt::CaseInsensitive);
            item->setHidden(!match);
        }
    });
} 