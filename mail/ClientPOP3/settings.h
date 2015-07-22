/*
 * The file encryption settings. Auxiliary dialog windows.
*/

#ifndef SETTINGS_H
#define SETTINGS_H

#include <QDialog>
#include <QMessageBox>

#include "clientpop3.h"

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

    QString Password;

private slots:
    void slotMode(void);
    void slotCloseForm(void);
    void slotModeSecretKey(void);
    void slotSelectAlgorithm(void);
};

#endif // SETTINGS_H
