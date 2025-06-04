#ifndef HEADERWIDGET_H
#define HEADERWIDGET_H

#include <QWidget>
#include <QPushButton>

class HeaderWidget : public QWidget {
    Q_OBJECT
public:
    explicit HeaderWidget(QWidget *parent = nullptr);
    QPushButton* accountButton() const;

private:
    QPushButton* m_accountBtn;
};

#endif // HEADERWIDGET_H