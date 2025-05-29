#ifndef SIDENAVWIDGET_H
#define SIDENAVWIDGET_H

#include <QWidget>
#include <QPushButton>

class SideNavWidget : public QWidget {
    Q_OBJECT
public:
    explicit SideNavWidget(QWidget *parent = nullptr);
    void setActiveTab(const QString &tabName);

private:
    QPushButton *createNavButton(const QString &text, const QString &iconPath);
};

#endif // SIDENAVWIDGET_H