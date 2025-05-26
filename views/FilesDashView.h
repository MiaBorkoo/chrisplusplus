#ifndef FILESDASHVIEW_H
#define FILESDASHVIEW_H

#include <QWidget>
#include "HeaderWidget.h"
#include "SideNavWidget.h"

class FilesDashView : public QWidget {
    Q_OBJECT
public:
    explicit FilesDashView(QWidget *parent = nullptr);

private:
    HeaderWidget *header;
    SideNavWidget *sideNav;
};

#endif // FILESDASHVIEW_H
