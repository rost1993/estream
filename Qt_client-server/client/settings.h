#ifndef SETTINGS_H
#define SETTINGS_H

#include <QDialog>
#include <QMessageBox>

#include "client.h"

namespace Ui {
class Settings;
}

class Settings : public QDialog
{
    Q_OBJECT

signals:
    void sendData(QString, int);

public:
    explicit Settings(int security, QWidget *parent = 0);
    ~Settings();

private:
    Ui::Settings *ui;

private slots:
    void slotSelectAlgorithm();
    void slotModeSecretKey();
    void slotCloseForm();
    void slotMode();
};

#endif // SETTINGS_H
