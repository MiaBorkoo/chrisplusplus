#ifndef SHAREDDASHCONTROLLER_H
#define SHAREDDASHCONTROLLER_H

#include <QObject>
#include "../views/SharedDashView.h"

class SharedDashController : public QObject {
    Q_OBJECT
public:
    explicit SharedDashController(SharedDashView *view, QObject *parent = nullptr);

private:
    SharedDashView *view;
    void connectSignals();
};

#endif // SHAREDDASHCONTROLLER_H 