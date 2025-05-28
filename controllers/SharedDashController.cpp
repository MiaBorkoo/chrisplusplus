#include "SharedDashController.h"
#include <QListWidget>
#include <QListWidgetItem>
#include <QLineEdit>
#include <QLabel>

SharedDashController::SharedDashController(SharedDashView *view, QObject *parent)
    : QObject(parent), view(view) {
    connectSignals();
}

void SharedDashController::connectSignals() {
    connect(view->getSearchBar(), &QLineEdit::textChanged, this, [this](const QString &query) {
        QListWidget *list = view->getFileList();
        for (int i = 0; i < list->count(); ++i) {
            QListWidgetItem *item = list->item(i);
            QWidget *widget = list->itemWidget(item);
            QLabel *fileLabel = widget->findChild<QLabel*>();
            bool match = fileLabel && fileLabel->text().contains(query, Qt::CaseInsensitive);
            item->setHidden(!match);
        }
    });
} 